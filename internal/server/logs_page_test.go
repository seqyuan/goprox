package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/seqyuan/goprox/internal/config"
	"github.com/seqyuan/goprox/internal/eventlog"
)

func logsServer(t *testing.T, dir string) *Server {
	t.Helper()
	filesUser(t, dir, t.TempDir()) // one files card so access events can be produced
	return New(&config.StateConfig{
		Server: config.ServerState{Host: "127.0.0.1", Port: 30152},
		Auth:   config.AuthState{SessionSecret: "testsecret", SessionTTL: 86400},
	}, dir)
}

func TestLogsPageRequiresLogin(t *testing.T) {
	srv := logsServer(t, t.TempDir())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/logs", nil)
	req.Host = "gw"
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "/login?next=") {
		t.Fatalf("status=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}
}

// Opening a card must leave an access entry in the user's own history, which the
// logs page and the JSON endpoint then show.
func TestLogsShowOwnAccessEvents(t *testing.T) {
	srv := logsServer(t, t.TempDir())
	cookie := aliceSessionCookie()

	req := httptest.NewRequest("GET", "/proxy/alice/data/", nil)
	req.Host = "gw"
	req.Header.Set("Cookie", cookie)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("card status = %d", rec.Code)
	}

	// Page.
	req = httptest.NewRequest("GET", "/logs", nil)
	req.Host = "gw"
	req.Header.Set("Cookie", cookie)
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("logs page status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"日志", "数据盘", "成功", "/proxy/alice/data/"} {
		if !strings.Contains(body, want) {
			t.Errorf("logs page missing %q", want)
		}
	}

	// JSON.
	req = httptest.NewRequest("GET", "/api/logs?limit=10", nil)
	req.Host = "gw"
	req.Header.Set("Cookie", cookie)
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"kind":"access"`) {
		t.Fatalf("logs API = %d %s", rec.Code, rec.Body.String())
	}
}

func TestLogsAPIRequiresLogin(t *testing.T) {
	srv := logsServer(t, t.TempDir())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/logs", nil)
	req.Host = "gw"
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// Static subresources must not fill the history: one page load fetches dozens.
func TestLogsSkipStaticAssets(t *testing.T) {
	srv := logsServer(t, t.TempDir())
	cookie := aliceSessionCookie()

	for _, p := range []string{"/proxy/alice/data/logo.png", "/proxy/alice/data/app.js", "/proxy/alice/data/style.css"} {
		req := httptest.NewRequest("GET", p, nil)
		req.Host = "gw"
		req.Header.Set("Cookie", cookie)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
	}
	if n := len(srv.events.List("alice", 0)); n != 0 {
		t.Fatalf("static requests were recorded (%d events)", n)
	}
}

// A proxy failure is recorded with its reason, which is the whole point of the
// logs page.
func TestLogsRecordProxyFailure(t *testing.T) {
	dir := t.TempDir()
	// A card pointing at a closed port: every request fails to connect.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	cfgPath := config.UserConfigPath(dir, "alice")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0700); err != nil {
		t.Fatal(err)
	}
	cfg := "auth:\n  password_hash: \"" + strings.Repeat("1", 64) + "\"\nservices:\n" +
		"  - id: app\n    name: App\n    host: 127.0.0.1\n    port: " + strconv.Itoa(port) + "\n    path: /app\n    websocket: true\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	srv := New(&config.StateConfig{
		Server: config.ServerState{Host: "127.0.0.1", Port: 30152},
		Auth:   config.AuthState{SessionSecret: "testsecret", SessionTTL: 86400},
	}, dir)

	req := httptest.NewRequest("GET", "/proxy/alice/app/", nil)
	req.Host = "gw"
	req.Header.Set("Cookie", aliceSessionCookie())
	srv.Handler().ServeHTTP(httptest.NewRecorder(), req)

	events := srv.events.List("alice", 0)
	if len(events) != 1 {
		t.Fatalf("events = %+v", events)
	}
	if events[0].OK || events[0].Kind != eventlog.KindAccess || !strings.Contains(events[0].Detail, "connection refused") {
		t.Fatalf("failure not recorded with reason: %+v", events[0])
	}
}

func TestEventLogIsPerUser(t *testing.T) {
	dir := t.TempDir()
	filesUser(t, dir, t.TempDir())
	writeBobConfig(t, dir)
	srv := New(&config.StateConfig{
		Server: config.ServerState{Host: "127.0.0.1", Port: 30152},
		Auth:   config.AuthState{SessionSecret: "testsecret", SessionTTL: 86400},
	}, dir)

	req := httptest.NewRequest("GET", "/proxy/alice/data/", nil)
	req.Host = "gw"
	req.Header.Set("Cookie", aliceSessionCookie())
	srv.Handler().ServeHTTP(httptest.NewRecorder(), req)

	if n := len(srv.events.List("bob", 0)); n != 0 {
		t.Fatalf("bob sees %d of alice's events", n)
	}
	if n := len(srv.events.List("alice", 0)); n != 1 {
		t.Fatalf("alice events = %d", n)
	}
}
