package tuya

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"encoding/json"
	"net"
	"testing"
	"time"
)

const testKey = "0123456789abcdef"

// fakeDevice emulates the device side of the protocol for one version.
type fakeDevice struct {
	t   *testing.T
	ver string
	dps map[string]any
	ln  net.Listener
}

func newFakeDevice(t *testing.T, ver string) *fakeDevice {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeDevice{t: t, ver: ver, ln: ln, dps: map[string]any{"101": "cancel", "103": "cancel", "105": float64(0)}}
	go f.serve()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakeDevice) addr() string { return f.ln.Addr().String() }

// devPack builds a device->client frame (with 4-byte return code).
func devPack(ver string, key []byte, seq, cmd uint32, data []byte, header bool) []byte {
	rc := []byte{0, 0, 0, 0}
	switch ver {
	case "3.5":
		if header {
			data = append(versionHeader(ver), data...)
		}
		return pack(ver, key, seq, cmd, append(rc, data...))
	case "3.4":
		if header {
			data = append(versionHeader(ver), data...)
		}
		var ct []byte
		if len(data) > 0 {
			ct = ecbEncrypt(key, pkcs7Pad(data))
		}
		return pack(ver, key, seq, cmd, append(rc, ct...))
	default:
		var ct []byte
		if len(data) > 0 {
			ct = ecbEncrypt(key, pkcs7Pad(data))
			if header {
				ct = append(versionHeader(ver), ct...)
			}
		}
		return pack(ver, key, seq, cmd, append(rc, ct...))
	}
}

func (f *fakeDevice) serve() {
	for {
		nc, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(nc)
	}
}

func (f *fakeDevice) handle(nc net.Conn) {
	defer nc.Close()
	key := []byte(testKey)
	lk := []byte(testKey)
	var buf []byte
	tmp := make([]byte, 4096)
	var localNonce []byte
	remoteNonce := []byte("fedcba9876543210")
	read := func() (Frame, bool) {
		for {
			raw, n, err := splitFrame(buf)
			if err != nil {
				f.t.Errorf("device split: %v", err)
				return Frame{}, false
			}
			if n > 0 && raw != nil {
				raw = append([]byte{}, raw...)
				buf = buf[n:]
				fr, err := unpack(f.ver, key, raw)
				if err != nil {
					f.t.Logf("device unpack: %v", err)
					return Frame{}, false
				}
				return fr, true
			}
			_ = nc.SetReadDeadline(time.Now().Add(3 * time.Second))
			m, err := nc.Read(tmp)
			if m > 0 {
				buf = append(buf, tmp[:m]...)
				continue
			}
			if err != nil {
				return Frame{}, false
			}
		}
	}
	for {
		fr, ok := read()
		if !ok {
			return
		}
		switch fr.Cmd {
		case CmdSessKeyNegStart:
			localNonce = append([]byte{}, fr.Payload...)
			resp := append(append([]byte{}, remoteNonce...), hmacSHA256(lk, localNonce)...)
			nc.Write(devPack(f.ver, lk, 1, CmdSessKeyNegResp, resp, false))
		case CmdSessKeyNegFinish:
			if !hmac.Equal(fr.Payload, hmacSHA256(lk, remoteNonce)) {
				f.t.Errorf("client hmac mismatch")
				return
			}
			key = deriveSessionKey(f.ver, lk, localNonce, remoteNonce)
		case CmdDPQuery, CmdDPQueryNew:
			b, _ := json.Marshal(map[string]any{"devId": "x", "dps": f.dps})
			nc.Write(devPack(f.ver, key, 2, fr.Cmd, b, false))
		case CmdControl, CmdControlNew:
			var m struct {
				DPS  map[string]any `json:"dps"`
				Data struct {
					DPS map[string]any `json:"dps"`
				} `json:"data"`
				Protocol int `json:"protocol"`
			}
			if err := json.Unmarshal(fr.Payload, &m); err != nil {
				f.t.Errorf("control payload %q: %v", fr.Payload, err)
				return
			}
			d := m.DPS
			if fr.Cmd == CmdControlNew {
				if m.Protocol != 5 {
					f.t.Errorf("expected protocol 5")
				}
				d = m.Data.DPS
			}
			for k, v := range d {
				f.dps[k] = v
			}
			nc.Write(devPack(f.ver, key, 3, fr.Cmd, nil, false)) // bare ack
			var push []byte
			if fr.Cmd == CmdControlNew {
				push, _ = json.Marshal(map[string]any{"protocol": 4, "t": 1, "data": map[string]any{"dps": d}})
			} else {
				push, _ = json.Marshal(map[string]any{"devId": "x", "dps": d, "t": 1})
			}
			nc.Write(devPack(f.ver, key, 4, CmdStatus, push, true))
		}
	}
}

func TestProtocols(t *testing.T) {
	for _, ver := range []string{"3.3", "3.4", "3.5"} {
		t.Run(ver, func(t *testing.T) {
			fd := newFakeDevice(t, ver)
			d := &Device{ID: "bf123", Address: fd.addr(), LocalKey: testKey, Version: ver, Timeout: 2 * time.Second}
			st, err := d.Status()
			if err != nil {
				t.Fatalf("status: %v", err)
			}
			if st["103"] != "cancel" {
				t.Fatalf("unexpected status %v", st)
			}
			res, err := d.Set(map[string]any{"103": "recall2"})
			if err != nil {
				t.Fatalf("set: %v", err)
			}
			if res["103"] != "recall2" {
				t.Fatalf("unexpected set result %v", res)
			}
			st, err = d.Status()
			if err != nil || st["103"] != "recall2" {
				t.Fatalf("status after set: %v %v", st, err)
			}
		})
	}
}

func TestWrongKey(t *testing.T) {
	for _, ver := range []string{"3.3", "3.4", "3.5"} {
		fd := newFakeDevice(t, ver)
		_ = fd
		d := &Device{ID: "bf123", Address: fd.addr(), LocalKey: "ffffffffffffffff", Version: ver, Timeout: 500 * time.Millisecond}
		if _, err := d.Status(); err == nil {
			t.Errorf("%s: expected error with wrong key", ver)
		}
	}
}

func TestPack55AALayout(t *testing.T) {
	f := pack("3.3", []byte(testKey), 1, CmdHeartbeat, nil)
	if binary.BigEndian.Uint32(f) != prefix55AA || binary.BigEndian.Uint32(f[len(f)-4:]) != suffix55AA {
		t.Fatal("bad prefix/suffix")
	}
	if binary.BigEndian.Uint32(f[12:]) != 8 || len(f) != 24 {
		t.Fatalf("bad length field: % x", f)
	}
	if !bytes.Equal(f[4:8], []byte{0, 0, 0, 1}) {
		t.Fatal("bad seq")
	}
}
