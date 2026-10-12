package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/seqyuan/goprox/internal/config"
)

// A configured auth_bootstrap must turn an unauthenticated HTML page request
// (dsh's raw 401) into a browser-visible 302 carrying the token, pointing back
// at the gateway path rather than the loopback backend.
func TestBootstrapRedirectsUnauthenticatedPage(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, "dsh web authentication required; reopen the URL printed by dsh web.")
	}))
	defer backend.Close()

	host, port := splitHostPort(backend.Listener.Addr().String())
	svc := &config.ServiceConfig{
		Host: host, Port: mustAtoi(t, port), Path: "/dsh",
		AuthBootstrap: &config.AuthBootstrapConfig{Mode: config.BootstrapModeStatic, TokenValue: "tok-abcd"},
	}

	req := httptest.NewRequest("GET", "/proxy/alice/dsh/", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	fc := BuildProxyForwardContext(req, "alice", "/dsh", false)
	rp := NewReverseProxy(svc, fc)

	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	want := "/proxy/alice/dsh/?token=tok-abcd"
	if got := rec.Header().Get("Location"); got != want {
		t.Fatalf("Location = %q, want %q", got, want)
	}
	if body := rec.Body.String(); body != "" {
		t.Fatalf("bootstrap redirect must not carry the 401 body, got %q", body)
	}
}

// A browser that already carries the token must see the backend's own answer,
// not another redirect (otherwise a rejected token loops forever).
func TestBootstrapNoLoopWhenTokenPresent(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, "nope")
	}))
	defer backend.Close()

	host, port := splitHostPort(backend.Listener.Addr().String())
	svc := &config.ServiceConfig{
		Host: host, Port: mustAtoi(t, port), Path: "/dsh",
		AuthBootstrap: &config.AuthBootstrapConfig{Mode: config.BootstrapModeStatic, TokenValue: "tok"},
	}

	req := httptest.NewRequest("GET", "/proxy/alice/dsh/?token=stale", nil)
	req.Header.Set("Accept", "text/html")
	fc := BuildProxyForwardContext(req, "alice", "/dsh", false)
	rp := NewReverseProxy(svc, fc)

	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (no redirect loop)", rec.Code)
	}
	if rec.Body.String() != "nope" {
		t.Fatalf("backend body must pass through, got %q", rec.Body.String())
	}
}

// API/JSON calls and non-GET methods must never be converted.
func TestBootstrapIgnoresNonHTMLAndNonGET(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, "unauthorized")
	}))
	defer backend.Close()
	host, port := splitHostPort(backend.Listener.Addr().String())
	svc := &config.ServiceConfig{
		Host: host, Port: mustAtoi(t, port), Path: "/dsh",
		AuthBootstrap: &config.AuthBootstrapConfig{Mode: config.BootstrapModeStatic, TokenValue: "tok"},
	}

	cases := []struct {
		name   string
		method string
		accept string
	}{
		{"json api", "GET", "application/json"},
		{"no accept", "GET", ""},
		{"post page", "POST", "text/html"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/proxy/alice/dsh/", nil)
			if tc.accept != "" {
				req.Header.Set("Accept", tc.accept)
			}
			fc := BuildProxyForwardContext(req, "alice", "/dsh", false)
			rp := NewReverseProxy(svc, fc)
			rec := httptest.NewRecorder()
			rp.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 (not bootstrapped)", rec.Code)
			}
		})
	}
}

// A bare/root path (routed via referer or default_service) is not redirected.
func TestBootstrapOnlyOnProxyPrefix(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, "x")
	}))
	defer backend.Close()
	host, port := splitHostPort(backend.Listener.Addr().String())
	svc := &config.ServiceConfig{
		Host: host, Port: mustAtoi(t, port), Path: "/dsh",
		AuthBootstrap: &config.AuthBootstrapConfig{Mode: config.BootstrapModeStatic, TokenValue: "tok"},
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept", "text/html")
	fc := BuildProxyForwardContext(req, "alice", "/dsh", false) // OriginalPath == "/"
	rp := NewReverseProxy(svc, fc)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (bare path not bootstrapped)", rec.Code)
	}
}

func TestBootstrapTokenFromFile(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "token")
	os.WriteFile(plain, []byte("file-token\n"), 0600)
	if tok, ok := bootstrapToken(&config.AuthBootstrapConfig{Mode: config.BootstrapModeFile, TokenFile: plain}); !ok || tok != "file-token" {
		t.Fatalf("file token = %q,%v; want file-token,true", tok, ok)
	}

	logPath := filepath.Join(dir, "dsh.log")
	os.WriteFile(logPath, []byte(
		"starting...\ndsh web: http://127.0.0.1:3080/?token=OLD\nrestart\ndsh web: http://127.0.0.1:3080/?token=NEW\n",
	), 0600)
	b := &config.AuthBootstrapConfig{Mode: config.BootstrapModeLog, TokenLog: logPath, TokenRegex: `\?token=([A-Za-z0-9_.-]+)`}
	if tok, ok := bootstrapToken(b); !ok || tok != "NEW" {
		t.Fatalf("log token = %q,%v; want NEW,true (last match wins)", tok, ok)
	}
}

func TestExtractTokenRegexWholeMatchWithoutGroup(t *testing.T) {
	if tok, ok := extractToken("token=abc123 done", `token=[a-z0-9]+`); !ok || tok != "token=abc123" {
		t.Fatalf("whole-match token = %q,%v; want token=abc123,true", tok, ok)
	}
}
