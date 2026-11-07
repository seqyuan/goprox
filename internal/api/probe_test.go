package api

import (
	"encoding/json"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seqyuan/goprox/internal/auth"
	"github.com/seqyuan/goprox/internal/config"
	"github.com/seqyuan/goprox/internal/eventlog"
)

func probeServer(t *testing.T) (*Handler, string) {
	t.Helper()
	configDir := t.TempDir()
	cfgPath := config.UserConfigPath(configDir, "alice")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte("auth:\n  password_hash: \""+strings.Repeat("1", 64)+"\"\nservices: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	reg := config.NewUserRegistry(configDir)
	reg.Reload()
	h := NewHandler(reg, "testsecret", 86400, "", "", auth.DefaultCookieNames())
	h.Events = eventlog.New(10)
	return h, configDir
}

func probePost(t *testing.T, h *Handler, id, origin string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/services/"+id+"/probe", nil)
	req.Header.Set("Cookie", auth.SetSessionCookie("testsecret", 86400, "alice", auth.SessionRev(strings.Repeat("1", 64)), false))
	req.Header.Set("Origin", origin)
	req.Host = "gw"
	rr := httptest.NewRecorder()
	if !h.ServeHTTP(rr, req) {
		t.Fatalf("probe route not claimed for %q", id)
	}
	return rr
}

type probeResponse struct {
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
	MS     int64  `json:"ms"`
}

func decodeProbe(t *testing.T, rr *httptest.ResponseRecorder) probeResponse {
	t.Helper()
	var out probeResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode probe response %q: %v", rr.Body.String(), err)
	}
	return out
}

func TestProbeReachableBackend(t *testing.T) {
	h, configDir := probeServer(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().(*net.TCPAddr)

	added, err := config.AddService(config.UserConfigPath(configDir, "alice"),
		config.ServiceConfig{Name: "app", Host: "127.0.0.1", Port: addr.Port, Path: "/app", WebSocket: true})
	if err != nil {
		t.Fatal(err)
	}
	h.Registry.Reload()

	rr := probePost(t, h, added.ID, "http://gw")
	if rr.Code != 200 {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if got := decodeProbe(t, rr); !got.OK || !strings.Contains(got.Detail, "端口可连") {
		t.Fatalf("probe = %+v", got)
	}

	// The probe is recorded in the user's history.
	events := h.Events.List("alice", 0)
	if len(events) != 1 || events[0].Kind != eventlog.KindProbe || !events[0].OK {
		t.Fatalf("probe not recorded: %+v", events)
	}
}

func TestProbeUnreachableBackend(t *testing.T) {
	h, configDir := probeServer(t)
	// Reserve a port, then close it: nothing is listening there.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	added, err := config.AddService(config.UserConfigPath(configDir, "alice"),
		config.ServiceConfig{Name: "dead", Host: "127.0.0.1", Port: port, Path: "/dead", WebSocket: true})
	if err != nil {
		t.Fatal(err)
	}
	h.Registry.Reload()

	got := decodeProbe(t, probePost(t, h, added.ID, "http://gw"))
	if got.OK || !strings.Contains(got.Detail, "连不上") {
		t.Fatalf("probe = %+v", got)
	}
}

func TestProbeFilesService(t *testing.T) {
	h, configDir := probeServer(t)
	dir := t.TempDir()
	ok, err := config.AddService(config.UserConfigPath(configDir, "alice"),
		config.ServiceConfig{Name: "data", Kind: config.ServiceKindFiles, Root: dir, Path: "/data"})
	if err != nil {
		t.Fatal(err)
	}
	h.Registry.Reload()
	if got := decodeProbe(t, probePost(t, h, ok.ID, "http://gw")); !got.OK || !strings.Contains(got.Detail, "目录可读") {
		t.Fatalf("probe = %+v", got)
	}
}

func TestProbeUnknownServiceAndCSRF(t *testing.T) {
	h, _ := probeServer(t)
	if rr := probePost(t, h, "nope", "http://gw"); rr.Code != 404 {
		t.Fatalf("unknown service status = %d", rr.Code)
	}
	if rr := probePost(t, h, "nope", "http://evil.example"); rr.Code != 403 {
		t.Fatalf("cross-origin probe status = %d, want 403", rr.Code)
	}
}
