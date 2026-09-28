// tvlift — small HTTP bridge between a Loxone Miniserver and a Tuya based
// motorised TV lift (e.g. monTEK TM1001CBE-L), controlled locally via LAN.
package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/chris/tvlift/tuya"
)

var version = "dev"

// Command is one named action: set data point DP to Value.
type Command struct {
	DP    string `json:"dp"`
	Value any    `json:"value"`
}

type Config struct {
	Listen   string
	Token    string
	AllowRaw bool
	Commands map[string]Command
	Device   *tuya.Device
}

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}

// parseValue converts "true"/"false" to bool, integers to int and leaves
// everything else as string (Tuya enum values are strings).
func parseValue(s string) any {
	switch strings.ToLower(s) {
	case "true":
		return true
	case "false":
		return false
	}
	if i, err := strconv.Atoi(s); err == nil {
		return i
	}
	return s
}

func loadConfig() (*Config, error) {
	dpMove := env("DP_MOVE", "101")
	dpMem := env("DP_MEMORY", "103")
	cmds := map[string]Command{
		"up":      {dpMove, "move_up"},
		"down":    {dpMove, "move_down"},
		"stop":    {dpMove, "cancel"},
		"recall1": {dpMem, "recall1"},
		"recall2": {dpMem, "recall2"},
		"recall3": {dpMem, "recall3"},
		"save1":   {dpMem, "mem1"},
		"save2":   {dpMem, "mem2"},
		"save3":   {dpMem, "mem3"},
	}
	// Overrides / additional commands: CMD_<NAME>=<dp>=<value>, e.g. CMD_RECALL1=4=position1
	for _, kv := range os.Environ() {
		k, v, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(k, "CMD_") || v == "" {
			continue
		}
		name := strings.ToLower(strings.TrimPrefix(k, "CMD_"))
		dp, val, ok := strings.Cut(v, "=")
		if !ok || dp == "" {
			return nil, fmt.Errorf("%s: expected <dp>=<value>, got %q", k, v)
		}
		cmds[name] = Command{dp, parseValue(val)}
	}

	timeout, err := time.ParseDuration(env("TUYA_TIMEOUT", "5s"))
	if err != nil {
		return nil, fmt.Errorf("TUYA_TIMEOUT: %w", err)
	}
	c := &Config{
		Listen:   env("LISTEN_ADDR", ":8088"),
		Token:    os.Getenv("API_TOKEN"),
		AllowRaw: env("ALLOW_RAW", "false") == "true",
		Commands: cmds,
		Device: &tuya.Device{
			ID:       os.Getenv("TUYA_DEVICE_ID"),
			Address:  os.Getenv("TUYA_IP"),
			LocalKey: os.Getenv("TUYA_LOCAL_KEY"),
			Version:  env("TUYA_VERSION", "3.4"),
			Timeout:  timeout,
		},
	}
	var missing []string
	for k, v := range map[string]string{"TUYA_DEVICE_ID": c.Device.ID, "TUYA_IP": c.Device.Address, "TUYA_LOCAL_KEY": c.Device.LocalKey} {
		if v == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("missing environment variables: %s", strings.Join(missing, ", "))
	}
	return c, nil
}

// withRetry runs fn and retries once — the lift's WiFi module occasionally
// drops a fresh TCP connection.
func withRetry[T any](fn func() (T, error)) (T, error) {
	v, err := fn()
	if err != nil {
		time.Sleep(700 * time.Millisecond)
		v, err = fn()
	}
	return v, err
}

// ---------------------------------------------------------------- HTTP

type server struct {
	cfg *Config
	log *slog.Logger
}

func (s *server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Token != "" {
			got := r.URL.Query().Get("token")
			if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
				got = strings.TrimPrefix(h, "Bearer ")
			} else if _, pw, ok := r.BasicAuth(); ok {
				got = pw // Loxone: http://tvlift:<token>@nas:8088
			}
			if subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.Token)) != 1 {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "unauthorized"})
				return
			}
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *server) run(w http.ResponseWriter, name string, cmd Command) {
	start := time.Now()
	res, err := withRetry(func() (map[string]any, error) {
		return s.cfg.Device.Set(map[string]any{cmd.DP: cmd.Value})
	})
	if err != nil {
		s.log.Error("command failed", "cmd", name, "dp", cmd.DP, "value", cmd.Value, "err", err)
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "cmd": name, "error": err.Error()})
		return
	}
	s.log.Info("command sent", "cmd", name, "dp", cmd.DP, "value", cmd.Value, "took", time.Since(start).Round(time.Millisecond))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cmd": name, "dp": cmd.DP, "value": cmd.Value, "reported": res})
}

func (s *server) handleCmd(w http.ResponseWriter, r *http.Request) {
	name := strings.ToLower(r.PathValue("name"))
	cmd, ok := s.cfg.Commands[name]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "unknown command " + name, "commands": s.cfg.Commands})
		return
	}
	s.run(w, name, cmd)
}

// handleRecall accepts the preset number, also as Loxone analog value ("2" or "2.000").
// 0 is ignored so that a radio button / reset value does not trigger a move.
func (s *server) handleRecall(w http.ResponseWriter, r *http.Request) {
	f, err := strconv.ParseFloat(strings.ReplaceAll(r.PathValue("n"), ",", "."), 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "preset must be a number"})
		return
	}
	n := int(f + 0.5)
	if n == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ignored": true})
		return
	}
	name := fmt.Sprintf("recall%d", n)
	cmd, ok := s.cfg.Commands[name]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "no preset " + strconv.Itoa(n)})
		return
	}
	s.run(w, name, cmd)
}

func (s *server) handleStatus(w http.ResponseWriter, r *http.Request) {
	dps, err := withRetry(s.cfg.Device.Status)
	if err != nil {
		s.log.Error("status failed", "err", err)
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if dp := r.PathValue("dp"); dp != "" {
		// plain value for a Loxone Virtual HTTP Input
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "%v\n", dps[dp])
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "dps": dps})
}

func (s *server) handleRaw(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.AllowRaw {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "set ALLOW_RAW=true to enable"})
		return
	}
	dp, val := r.URL.Query().Get("dp"), r.URL.Query().Get("value")
	if dp == "" || val == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "dp and value required"})
		return
	}
	s.run(w, "raw", Command{dp, parseValue(val)})
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	mux.HandleFunc("GET /api/commands", s.auth(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, s.cfg.Commands)
	}))
	mux.HandleFunc("GET /api/status", s.auth(s.handleStatus))
	mux.HandleFunc("GET /api/status/{dp}", s.auth(s.handleStatus))
	mux.HandleFunc("/api/cmd/{name}", s.auth(s.handleCmd))
	mux.HandleFunc("/api/recall/{n}", s.auth(s.handleRecall))
	mux.HandleFunc("/api/set", s.auth(s.handleRaw))
	return mux
}

// ---------------------------------------------------------------- CLI

func usage() {
	fmt.Fprint(os.Stderr, `tvlift `+version+` — Loxone <-> Tuya TV lift bridge

Usage:
  tvlift [serve]            start HTTP server (default)
  tvlift status             print all data points of the lift
  tvlift cmd <name>         run a named command (up, down, stop, recall1..3, save1..3)
  tvlift set <dp> <value>   write a raw data point (for discovery)
  tvlift healthcheck        check the local HTTP server (for Docker)

Configuration via environment: TUYA_DEVICE_ID, TUYA_IP, TUYA_LOCAL_KEY,
TUYA_VERSION (3.3|3.4|3.5, default 3.4), LISTEN_ADDR (:8088), API_TOKEN,
DP_MOVE (101), DP_MEMORY (103), CMD_<NAME>=<dp>=<value>, ALLOW_RAW.
`)
}

func printJSON(v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	args := os.Args[1:]
	sub := "serve"
	if len(args) > 0 {
		sub = args[0]
	}

	if sub == "healthcheck" {
		port := env("LISTEN_ADDR", ":8088")
		if i := strings.LastIndex(port, ":"); i >= 0 {
			port = port[i+1:]
		}
		cl := http.Client{Timeout: 3 * time.Second}
		resp, err := cl.Get("http://127.0.0.1:" + port + "/healthz")
		if err != nil || resp.StatusCode != 200 {
			os.Exit(1)
		}
		return
	}
	if sub == "-h" || sub == "--help" || sub == "help" {
		usage()
		return
	}

	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		usage()
		os.Exit(2)
	}

	switch sub {
	case "status":
		dps, err := cfg.Device.Status()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		printJSON(dps)
	case "cmd":
		if len(args) < 2 {
			usage()
			os.Exit(2)
		}
		c, ok := cfg.Commands[strings.ToLower(args[1])]
		if !ok {
			fmt.Fprintln(os.Stderr, "unknown command", args[1])
			os.Exit(2)
		}
		res, err := cfg.Device.Set(map[string]any{c.DP: c.Value})
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		printJSON(res)
	case "set":
		if len(args) < 3 {
			usage()
			os.Exit(2)
		}
		res, err := cfg.Device.Set(map[string]any{args[1]: parseValue(args[2])})
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		printJSON(res)
	case "serve":
		s := &server{cfg: cfg, log: logger}
		srv := &http.Server{Addr: cfg.Listen, Handler: s.routes(), ReadHeaderTimeout: 5 * time.Second}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		go func() {
			<-ctx.Done()
			sc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(sc)
		}()
		logger.Info("tvlift started", "version", version, "listen", cfg.Listen, "device", cfg.Device.Address,
			"protocol", cfg.Device.Version, "auth", cfg.Token != "")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server", "err", err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(2)
	}
}
