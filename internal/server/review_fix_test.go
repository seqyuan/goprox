package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seqyuan/goprox/internal/auth"
	"github.com/seqyuan/goprox/internal/config"
)

func newTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	configDir := t.TempDir()
	cfgPath := config.UserConfigPath(configDir, "alice")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0700); err != nil {
		t.Fatal(err)
	}
	hash := auth.HashPassword("pw")
	cfg := "auth:\n  password_hash: \"" + hash + "\"\nservices:\n  - id: jupyter\n    name: Jupyter\n    host: 127.0.0.1\n    port: 8888\n    path: /jupyter\n    websocket: true\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	srv := New(&config.StateConfig{
		Server: config.ServerState{Host: "127.0.0.1", Port: 30152},
		Auth:   config.AuthState{SessionSecret: "testsecret", SessionTTL: 86400},
	}, configDir)
	return srv, cfgPath
}

func newBackend(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
}

// A logged-in user with a route cookie visiting the bare path /jupyter must be
// redirected to the proxied URL, not forwarded to the backend (which 404s).
func TestBarePathRedirectsEvenWithRouteCookie(t *testing.T) {
	backend := newBackend(t)
	defer backend.Close()
	addr := backend.Listener.Addr().String()
	i := strings.LastIndex(addr, ":")
	host, port := addr[:i], addr[i+1:]

	configDir := t.TempDir()
	cfgPath := config.UserConfigPath(configDir, "alice")
	os.MkdirAll(filepath.Dir(cfgPath), 0700)
	cfg := fmt.Sprintf("auth:\n  password_hash: \"%s\"\nservices:\n  - id: jupyter\n    name: Jupyter\n    host: %s\n    port: %s\n    path: /jupyter\n    websocket: true\n", strings.Repeat("1", 64), host, port)
	os.WriteFile(cfgPath, []byte(cfg), 0600)

	srv := New(&config.StateConfig{
		Server: config.ServerState{Host: "127.0.0.1", Port: 30152},
		Auth:   config.AuthState{SessionSecret: "testsecret", SessionTTL: 86400},
	}, configDir)

	cookies := auth.SetSessionCookie("testsecret", 86400, "alice", auth.SessionRev(strings.Repeat("1", 64)), false) + "; " + auth.SetRouteCookie("/proxy/alice/jupyter")
	req := httptest.NewRequest("GET", "/jupyter", nil)
	req.Header.Set("Cookie", cookies)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusFound || !strings.HasPrefix(rr.Header().Get("Location"), "/proxy/alice/jupyter") {
		t.Fatalf("expected redirect to /proxy/alice/jupyter/, got %d location=%q", rr.Code, rr.Header().Get("Location"))
	}
}

// An unauthenticated /proxy request must land on the login page and return to
// the original service after login (next parameter round-trip).
func TestLoginNextRoundTrip(t *testing.T) {
	srv, _ := newTestServer(t)

	// Unauthenticated proxy request -> redirect to /login?next=...
	req := httptest.NewRequest("GET", "/proxy/alice/jupyter/lab", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	loc := rr.Header().Get("Location")
	if rr.Code != http.StatusFound || !strings.HasPrefix(loc, "/login?next=") {
		t.Fatalf("expected /login?next= redirect, got %d location=%q", rr.Code, loc)
	}

	// GET /login renders the login page (no longer a bare redirect to "/").
	req = httptest.NewRequest("GET", loc, nil)
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `name="next"`) {
		t.Fatalf("expected login page with next field, got %d", rr.Code)
	}

	// POST /login with valid credentials redirects to the original proxy URL.
	form := url.Values{"username": {"alice"}, "password": {"pw"}, "next": {"/proxy/alice/jupyter/lab"}}
	req = httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/proxy/alice/jupyter/lab" {
		t.Fatalf("expected redirect to original service, got %d location=%q", rr.Code, rr.Header().Get("Location"))
	}
}

// The next parameter must not allow open redirects.
func TestLoginRejectsOpenRedirect(t *testing.T) {
	srv, _ := newTestServer(t)
	form := url.Values{"username": {"alice"}, "password": {"pw"}, "next": {"//evil.example.com"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Header().Get("Location") != "/" {
		t.Fatalf("expected fallback redirect to /, got %q", rr.Header().Get("Location"))
	}
}

// SPA backends call bare /api/* paths that must still be routed to the proxied
// backend via the route cookie (the bare-path redirect must not hijack them).
func TestAPIStillForwardsViaRouteCookie(t *testing.T) {
	var gotPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Write([]byte("ok"))
	}))
	defer backend.Close()
	addr := backend.Listener.Addr().String()
	i := strings.LastIndex(addr, ":")
	host, port := addr[:i], addr[i+1:]

	configDir := t.TempDir()
	cfgPath := config.UserConfigPath(configDir, "alice")
	os.MkdirAll(filepath.Dir(cfgPath), 0700)
	cfg := fmt.Sprintf("auth:\n  password_hash: \"%s\"\nservices:\n  - id: jupyter\n    name: Jupyter\n    host: %s\n    port: %s\n    path: /jupyter\n    websocket: true\n", strings.Repeat("1", 64), host, port)
	os.WriteFile(cfgPath, []byte(cfg), 0600)

	srv := New(&config.StateConfig{
		Server: config.ServerState{Host: "127.0.0.1", Port: 30152},
		Auth:   config.AuthState{SessionSecret: "testsecret", SessionTTL: 86400},
	}, configDir)

	cookies := auth.SetSessionCookie("testsecret", 86400, "alice", auth.SessionRev(strings.Repeat("1", 64)), false) + "; " + auth.SetRouteCookie("/proxy/alice/jupyter")
	req := httptest.NewRequest("GET", "/api/contents", nil)
	req.Header.Set("Cookie", cookies)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != 200 || gotPath != "/api/contents" {
		t.Fatalf("expected /api/contents forwarded to backend, got status=%d backendPath=%q", rr.Code, gotPath)
	}
}

// Cross-site login POSTs must be rejected (login CSRF), while same-origin
// login still works.
func TestLoginRejectsCrossOrigin(t *testing.T) {
	srv, _ := newTestServer(t)
	form := url.Values{"username": {"alice"}, "password": {"pw"}}

	// Cross-site page attempting login CSRF.
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://evil.example")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-origin login, got %d", rr.Code)
	}

	// Same-origin browser login must still succeed.
	req2 := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Origin", "http://gw:30152")
	req2.Host = "gw:30152"
	rr2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusFound {
		t.Fatalf("expected 302 for same-origin login, got %d", rr2.Code)
	}
}
