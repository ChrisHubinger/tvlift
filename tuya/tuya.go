// Package tuya implements a minimal client for the Tuya local LAN protocol
// (versions 3.3, 3.4 and 3.5) — just enough to read and write data points.
package tuya

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"net"
	"strconv"
	"sync"
	"time"
)

// Command codes.
const (
	CmdSessKeyNegStart  uint32 = 3
	CmdSessKeyNegResp   uint32 = 4
	CmdSessKeyNegFinish uint32 = 5
	CmdControl          uint32 = 7
	CmdStatus           uint32 = 8
	CmdHeartbeat        uint32 = 9
	CmdDPQuery          uint32 = 10
	CmdControlNew       uint32 = 13
	CmdDPQueryNew       uint32 = 16
)

const (
	prefix55AA uint32 = 0x000055AA
	suffix55AA uint32 = 0x0000AA55
	prefix6699 uint32 = 0x00006699
	suffix6699 uint32 = 0x00009966
)

// Port is the TCP port Tuya devices listen on.
const Port = 6668

// Device describes one Tuya device on the LAN.
type Device struct {
	ID       string
	Address  string // IP or host name, optionally with :port
	LocalKey string // 16 characters
	Version  string // "3.3", "3.4" or "3.5"
	Timeout  time.Duration

	mu sync.Mutex // Tuya devices only accept very few parallel connections
}

// Status reads all data points of the device.
func (d *Device) Status() (map[string]any, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	c, err := d.dial()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.status()
}

// Set writes one or more data points. It returns the data points the device
// reported back (may be empty when the device only acknowledges).
func (d *Device) Set(dps map[string]any) (map[string]any, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	c, err := d.dial()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.set(dps)
}

func (d *Device) timeout() time.Duration {
	if d.Timeout > 0 {
		return d.Timeout
	}
	return 5 * time.Second
}

func (d *Device) dial() (*conn, error) {
	switch d.Version {
	case "3.3", "3.4", "3.5":
	default:
		return nil, fmt.Errorf("unsupported protocol version %q (use 3.3, 3.4 or 3.5)", d.Version)
	}
	if len(d.LocalKey) != 16 {
		return nil, fmt.Errorf("local key must be 16 characters, got %d", len(d.LocalKey))
	}
	addr := d.Address
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, strconv.Itoa(Port))
	}
	nc, err := net.DialTimeout("tcp", addr, d.timeout())
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", addr, err)
	}
	c := &conn{
		nc:       nc,
		dev:      d,
		ver:      d.Version,
		localKey: []byte(d.LocalKey),
		key:      []byte(d.LocalKey),
		timeout:  d.timeout(),
	}
	if c.ver != "3.3" {
		if err := c.negotiate(); err != nil {
			nc.Close()
			return nil, fmt.Errorf("session key negotiation: %w", err)
		}
	}
	return c, nil
}

// conn is one TCP session with a device.
type conn struct {
	nc       net.Conn
	dev      *Device
	ver      string
	localKey []byte
	key      []byte // session key (3.4/3.5) or local key (3.3)
	seq      uint32
	rbuf     []byte
	timeout  time.Duration
}

func (c *conn) Close() error { return c.nc.Close() }

// Frame is a decoded protocol message.
type Frame struct {
	Cmd     uint32
	Payload []byte // decrypted, without return code or version header
}

func noVersionHeader(cmd uint32) bool {
	switch cmd {
	case CmdDPQuery, CmdDPQueryNew, CmdHeartbeat, CmdSessKeyNegStart, CmdSessKeyNegResp, CmdSessKeyNegFinish, CmdStatus:
		return true
	}
	return false
}

func versionHeader(ver string) []byte {
	return append([]byte(ver), make([]byte, 12)...)
}

// ---------------------------------------------------------------- crypto

func pkcs7Pad(b []byte) []byte {
	n := aes.BlockSize - len(b)%aes.BlockSize
	return append(append([]byte{}, b...), bytes.Repeat([]byte{byte(n)}, n)...)
}

func pkcs7Unpad(b []byte) ([]byte, error) {
	if len(b) == 0 || len(b)%aes.BlockSize != 0 {
		return nil, errors.New("invalid padded length")
	}
	n := int(b[len(b)-1])
	if n == 0 || n > aes.BlockSize || n > len(b) {
		return nil, errors.New("invalid padding")
	}
	for _, v := range b[len(b)-n:] {
		if int(v) != n {
			return nil, errors.New("invalid padding")
		}
	}
	return b[:len(b)-n], nil
}

func ecbEncrypt(key, plain []byte) []byte {
	blk, _ := aes.NewCipher(key)
	out := make([]byte, len(plain))
	for i := 0; i < len(plain); i += aes.BlockSize {
		blk.Encrypt(out[i:i+aes.BlockSize], plain[i:i+aes.BlockSize])
	}
	return out
}

func ecbDecrypt(key, ct []byte) ([]byte, error) {
	if len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext length %d is not a multiple of 16", len(ct))
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ct))
	for i := 0; i < len(ct); i += aes.BlockSize {
		blk.Decrypt(out[i:i+aes.BlockSize], ct[i:i+aes.BlockSize])
	}
	return out, nil
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func newGCM(key []byte) cipher.AEAD {
	blk, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(blk)
	return g
}

// ---------------------------------------------------------------- framing

// encodePayload applies the version-specific header and ECB encryption.
// For 3.5 encryption happens in pack (AES-GCM over the whole payload).
func encodePayload(ver string, key []byte, cmd uint32, data []byte) []byte {
	switch ver {
	case "3.3":
		enc := ecbEncrypt(key, pkcs7Pad(data))
		if noVersionHeader(cmd) {
			return enc
		}
		return append(versionHeader(ver), enc...)
	case "3.4":
		if !noVersionHeader(cmd) {
			data = append(versionHeader(ver), data...)
		}
		return ecbEncrypt(key, pkcs7Pad(data))
	default: // 3.5
		if !noVersionHeader(cmd) {
			data = append(versionHeader(ver), data...)
		}
		return data
	}
}

// pack builds a complete wire frame.
func pack(ver string, key []byte, seq, cmd uint32, payload []byte) []byte {
	if ver == "3.5" {
		iv := make([]byte, 12)
		_, _ = rand.Read(iv)
		hdr := make([]byte, 18)
		binary.BigEndian.PutUint32(hdr[0:], prefix6699)
		binary.BigEndian.PutUint16(hdr[4:], 0)
		binary.BigEndian.PutUint32(hdr[6:], seq)
		binary.BigEndian.PutUint32(hdr[10:], cmd)
		binary.BigEndian.PutUint32(hdr[14:], uint32(12+len(payload)+16))
		ct := newGCM(key).Seal(nil, iv, payload, hdr[4:])
		out := append(hdr, iv...)
		out = append(out, ct...)
		return binary.BigEndian.AppendUint32(out, suffix6699)
	}
	trailer := 4
	if ver == "3.4" {
		trailer = 32
	}
	hdr := make([]byte, 16)
	binary.BigEndian.PutUint32(hdr[0:], prefix55AA)
	binary.BigEndian.PutUint32(hdr[4:], seq)
	binary.BigEndian.PutUint32(hdr[8:], cmd)
	binary.BigEndian.PutUint32(hdr[12:], uint32(len(payload)+trailer+4))
	body := append(hdr, payload...)
	if ver == "3.4" {
		body = append(body, hmacSHA256(key, body)...)
	} else {
		body = binary.BigEndian.AppendUint32(body, crc32.ChecksumIEEE(body))
	}
	return binary.BigEndian.AppendUint32(body, suffix55AA)
}

// splitFrame extracts one raw frame from buf. It returns the frame, the
// number of bytes consumed, or n==0 when more data is needed.
func splitFrame(buf []byte) (frame []byte, n int, err error) {
	for len(buf) >= 4 {
		p := binary.BigEndian.Uint32(buf)
		if p == prefix55AA || p == prefix6699 {
			break
		}
		buf = buf[1:] // resync
		n++
	}
	if len(buf) < 4 {
		return nil, 0, nil
	}
	switch binary.BigEndian.Uint32(buf) {
	case prefix55AA:
		if len(buf) < 16 {
			return nil, 0, nil
		}
		l := int(binary.BigEndian.Uint32(buf[12:]))
		if l > 64*1024 {
			return nil, 0, fmt.Errorf("frame too large (%d)", l)
		}
		if len(buf) < 16+l {
			return nil, 0, nil
		}
		return buf[:16+l], n + 16 + l, nil
	default: // 6699
		if len(buf) < 18 {
			return nil, 0, nil
		}
		l := int(binary.BigEndian.Uint32(buf[14:]))
		if l > 64*1024 {
			return nil, 0, fmt.Errorf("frame too large (%d)", l)
		}
		if len(buf) < 18+l+4 {
			return nil, 0, nil
		}
		return buf[:18+l+4], n + 18 + l + 4, nil
	}
}

func stripRetcode(b []byte) []byte {
	if len(b) >= 4 && b[0] == 0 && b[1] == 0 && b[2] == 0 {
		return b[4:]
	}
	return b
}

func stripVersionHeader(b []byte) []byte {
	if len(b) >= 15 && b[0] == '3' && b[1] == '.' && b[3] < 0x20 {
		return b[15:]
	}
	return b
}

// unpack verifies and decrypts one raw frame.
func unpack(ver string, key []byte, raw []byte) (Frame, error) {
	prefix := binary.BigEndian.Uint32(raw)
	if prefix == prefix6699 {
		hdr := raw[:18]
		cmd := binary.BigEndian.Uint32(hdr[10:])
		body := raw[18 : len(raw)-4]
		if len(body) < 28 {
			return Frame{}, errors.New("6699 frame too short")
		}
		iv, ct := body[:12], body[12:]
		plain, err := newGCM(key).Open(nil, iv, ct, hdr[4:])
		if err != nil {
			return Frame{}, fmt.Errorf("gcm decrypt (wrong local key?): %w", err)
		}
		plain = stripVersionHeader(stripRetcode(plain))
		return Frame{Cmd: cmd, Payload: plain}, nil
	}

	cmd := binary.BigEndian.Uint32(raw[8:])
	trailer := 4
	if ver == "3.4" {
		trailer = 32
	}
	if len(raw) < 16+trailer+4 {
		return Frame{}, errors.New("frame too short")
	}
	end := len(raw) - 4 - trailer
	data := raw[16:end]
	if ver == "3.4" {
		if !hmac.Equal(hmacSHA256(key, raw[:end]), raw[end:end+32]) {
			return Frame{}, errors.New("hmac mismatch (wrong local key?)")
		}
	} else if crc32.ChecksumIEEE(raw[:end]) != binary.BigEndian.Uint32(raw[end:]) {
		return Frame{}, errors.New("crc mismatch")
	}

	// Device replies carry a 4-byte return code in front of the (encrypted) data.
	// Ciphertext is a multiple of 16 bytes, optionally preceded by a 15-byte
	// version header (3.3), so the remainder tells us whether it is there.
	switch len(data) % 16 {
	case 4, 3: // 4: retcode+ct, 3: retcode+header(15)+ct
		data = data[4:]
	}
	if len(data) == 0 {
		return Frame{Cmd: cmd}, nil
	}
	if ver == "3.3" {
		data = stripVersionHeader(data)
	}
	if len(data)%16 != 0 {
		// Some firmwares answer with plain text errors such as "data format error".
		return Frame{Cmd: cmd, Payload: data}, nil
	}
	plain, err := ecbDecrypt(key, data)
	if err != nil {
		return Frame{}, err
	}
	plain, err = pkcs7Unpad(plain)
	if err != nil {
		return Frame{}, fmt.Errorf("decrypt (wrong local key?): %w", err)
	}
	return Frame{Cmd: cmd, Payload: stripVersionHeader(plain)}, nil
}

// ---------------------------------------------------------------- session

func (c *conn) send(cmd uint32, data []byte) error {
	c.seq++
	frame := pack(c.ver, c.key, c.seq, cmd, encodePayload(c.ver, c.key, cmd, data))
	_ = c.nc.SetWriteDeadline(time.Now().Add(c.timeout))
	_, err := c.nc.Write(frame)
	return err
}

func (c *conn) recv(deadline time.Time) (Frame, error) {
	_ = c.nc.SetReadDeadline(deadline)
	tmp := make([]byte, 4096)
	for {
		raw, n, err := splitFrame(c.rbuf)
		if err != nil {
			return Frame{}, err
		}
		if n > 0 && raw != nil {
			raw = append([]byte{}, raw...)
			c.rbuf = c.rbuf[n:]
			return unpack(c.ver, c.key, raw)
		}
		m, err := c.nc.Read(tmp)
		if m > 0 {
			c.rbuf = append(c.rbuf, tmp[:m]...)
			continue
		}
		if err != nil {
			return Frame{}, err
		}
	}
}

func (c *conn) negotiate() error {
	localNonce := make([]byte, 16)
	_, _ = rand.Read(localNonce)
	c.key = c.localKey
	if err := c.send(CmdSessKeyNegStart, localNonce); err != nil {
		return err
	}
	deadline := time.Now().Add(c.timeout)
	var resp Frame
	for {
		f, err := c.recv(deadline)
		if err != nil {
			return err
		}
		if f.Cmd == CmdSessKeyNegResp {
			resp = f
			break
		}
	}
	if len(resp.Payload) < 48 {
		return fmt.Errorf("short negotiation response (%d bytes)", len(resp.Payload))
	}
	remoteNonce := resp.Payload[:16]
	if !hmac.Equal(resp.Payload[16:48], hmacSHA256(c.localKey, localNonce)) {
		return errors.New("device hmac mismatch (wrong local key?)")
	}
	if err := c.send(CmdSessKeyNegFinish, hmacSHA256(c.localKey, remoteNonce)); err != nil {
		return err
	}
	c.key = deriveSessionKey(c.ver, c.localKey, localNonce, remoteNonce)
	return nil
}

func deriveSessionKey(ver string, localKey, localNonce, remoteNonce []byte) []byte {
	x := make([]byte, 16)
	for i := range x {
		x[i] = localNonce[i] ^ remoteNonce[i]
	}
	if ver == "3.5" {
		return newGCM(localKey).Seal(nil, localNonce[:12], x, nil)[:16]
	}
	return ecbEncrypt(localKey, x)
}

// ---------------------------------------------------------------- commands

func (c *conn) now() int64 { return time.Now().Unix() }

func (c *conn) status() (map[string]any, error) {
	var cmd uint32
	var body []byte
	if c.ver == "3.3" {
		cmd = CmdDPQuery
		id := c.dev.ID
		body, _ = json.Marshal(map[string]any{"gwId": id, "devId": id, "uid": id, "t": strconv.FormatInt(c.now(), 10)})
	} else {
		cmd = CmdDPQueryNew
		body = []byte("{}")
	}
	if err := c.send(cmd, body); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(c.timeout)
	for {
		f, err := c.recv(deadline)
		if err != nil {
			return nil, err
		}
		if len(f.Payload) == 0 {
			continue
		}
		dps, err := parseDPS(f.Payload)
		if err != nil {
			return nil, err
		}
		if dps != nil {
			return dps, nil
		}
	}
}

func (c *conn) set(dps map[string]any) (map[string]any, error) {
	var cmd uint32
	var body []byte
	if c.ver == "3.3" {
		cmd = CmdControl
		id := c.dev.ID
		body, _ = json.Marshal(map[string]any{"devId": id, "uid": id, "t": strconv.FormatInt(c.now(), 10), "dps": dps})
	} else {
		cmd = CmdControlNew
		body, _ = json.Marshal(map[string]any{"protocol": 5, "t": c.now(), "data": map[string]any{"dps": dps}})
	}
	if err := c.send(cmd, body); err != nil {
		return nil, err
	}
	// Wait for the ack and (usually) a status push. Only a missing ack is an error.
	acked := false
	deadline := time.Now().Add(c.timeout)
	for {
		f, err := c.recv(deadline)
		if err != nil {
			if acked {
				return map[string]any{}, nil
			}
			return nil, fmt.Errorf("no acknowledgement: %w", err)
		}
		if f.Cmd == cmd {
			acked = true
			if len(f.Payload) > 0 {
				if d, _ := parseDPS(f.Payload); d != nil {
					return d, nil
				}
				if !bytes.HasPrefix(f.Payload, []byte("{")) {
					return nil, fmt.Errorf("device error: %s", f.Payload)
				}
			}
			deadline = time.Now().Add(1500 * time.Millisecond)
			continue
		}
		if f.Cmd == CmdStatus {
			if d, _ := parseDPS(f.Payload); d != nil {
				return d, nil
			}
		}
	}
}

func parseDPS(b []byte) (map[string]any, error) {
	if !bytes.HasPrefix(bytes.TrimSpace(b), []byte("{")) {
		return nil, fmt.Errorf("device error: %q", b)
	}
	var m struct {
		DPS  map[string]any `json:"dps"`
		Data struct {
			DPS map[string]any `json:"dps"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse %q: %w", b, err)
	}
	if m.DPS != nil {
		return m.DPS, nil
	}
	return m.Data.DPS, nil
}
