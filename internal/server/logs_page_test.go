package server

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// A backend that answers with its own 4xx/5xx is a failed card access, not a
// successful one: the status the client received must drive the record.
// (Regression: every proxied access was logged as ok because recordAccess was
// handed status 0 and only proxy-level transport errors carried a reason.)
func TestLogsRecordBackendErrorStatus(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/missing":
			http.Error(w, "gone", http.StatusNotFound)
		case "/boom":
			http.Error(w, "kaboom", http.StatusInternalServerError)
		default:
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, "ok")
		}
	}))
	defer backend.Close()
	u, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	cfgPath := config.UserConfigPath(dir, "alice")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0700); err != nil {
		t.Fatal(err)
	}
	cfg := "auth:\n  password_hash: \"" + strings.Repeat("1", 64) + "\"\nservices:\n" +
		"  - id: app\n    name: App\n    host: " + host + "\n    port: " + portStr +
		"\n    path: /app\n    websocket: true\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	srv := New(&config.StateConfig{
		Server: config.ServerState{Host: "127.0.0.1", Port: 30152},
		Auth:   config.AuthState{SessionSecret: "testsecret", SessionTTL: 86400},
	}, dir)

	for _, path := range []string{
		"/proxy/alice/app/hello",
		"/proxy/alice/app/missing",
		"/proxy/alice/app/boom",
	} {
		req := httptest.NewRequest("GET", path, nil)
		req.Host = "gw"
		req.Header.Set("Cookie", aliceSessionCookie())
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code == 0 {
			t.Fatalf("%s: no status", path)
		}
	}

	events := srv.events.List("alice", 0)
	if len(events) != 3 {
		t.Fatalf("events = %+v", events)
	}
	// List returns newest first: 500, 404, 200.
	want := []struct {
		ok   bool
		code string
	}{
		{false, "500"},
		{false, "404"},
		{true, ""},
	}
	for i, w := range want {
		e := events[i]
		if e.Kind != eventlog.KindAccess || e.OK != w.ok {
			t.Fatalf("event %d = %+v, want ok=%v", i, e, w.ok)
		}
		if w.code != "" && !strings.Contains(e.Detail, w.code) {
			t.Fatalf("event %d detail = %q, want it to mention %s", i, e.Detail, w.code)
		}
	}
	// A failing record still names the request that failed.
	if !strings.Contains(events[0].Detail, "/proxy/alice/app/boom") {
		t.Fatalf("detail lost the request path: %q", events[0].Detail)
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

// The history must survive a gateway restart: a second Server built on the same
// config dir sees the events written by the first one.
func TestLogsPersistAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	filesUser(t, dir, t.TempDir())
	state := func() *config.StateConfig {
		return &config.StateConfig{
			Server: config.ServerState{Host: "127.0.0.1", Port: 30152},
			Auth:   config.AuthState{SessionSecret: "testsecret", SessionTTL: 86400},
		}
	}

	srv := New(state(), dir)
	req := httptest.NewRequest("GET", "/proxy/alice/data/", nil)
	req.Host = "gw"
	req.Header.Set("Cookie", aliceSessionCookie())
	srv.Handler().ServeHTTP(httptest.NewRecorder(), req)
	srv.events.Add("alice", eventlog.Event{Kind: eventlog.KindLogin, OK: true, Detail: "密码登录"})

	// "Restart": a fresh Server (and so a fresh in-memory ring) on the same dir.
	restarted := New(state(), dir)
	events := restarted.events.List("alice", 0)
	if len(events) < 2 {
		t.Fatalf("history lost across restart: %+v", events)
	}
	var sawAccess, sawLogin bool
	for _, e := range events {
		if e.Kind == eventlog.KindAccess && e.OK && e.Service == "数据盘" {
			sawAccess = true
		}
		if e.Kind == eventlog.KindLogin && strings.Contains(e.Detail, "密码") {
			sawLogin = true
		}
	}
	if !sawAccess || !sawLogin {
		t.Fatalf("missing events after restart: %+v", events)
	}
	if n := len(restarted.events.List("bob", 0)); n != 0 {
		t.Fatalf("bob sees %d of alice's events after restart", n)
	}
}

// log_retention_days: 0 keeps the history in memory only (no files).
func TestLogsMemoryOnlyWhenRetentionZero(t *testing.T) {
	dir := t.TempDir()
	filesUser(t, dir, t.TempDir())
	zero := 0
	srv := New(&config.StateConfig{
		Server: config.ServerState{Host: "127.0.0.1", Port: 30152, LogRetentionDays: &zero},
		Auth:   config.AuthState{SessionSecret: "testsecret", SessionTTL: 86400},
	}, dir)

	req := httptest.NewRequest("GET", "/proxy/alice/data/", nil)
	req.Host = "gw"
	req.Header.Set("Cookie", aliceSessionCookie())
	srv.Handler().ServeHTTP(httptest.NewRecorder(), req)

	if _, err := os.Stat(filepath.Join(dir, "logs")); !os.IsNotExist(err) {
		t.Fatal("retention 0 must not create a logs directory")
	}
	if len(srv.events.List("alice", 0)) != 1 {
		t.Fatal("memory history should still work")
	}
}
