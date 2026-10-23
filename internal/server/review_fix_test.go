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

// A pending 2FA setup token is bound to the user who started enrollment. A
// stale cookie from another account must not enroll that secret into the
// current user's account on a shared browser.
func TestTwoFASetupRejectsOtherUsersToken(t *testing.T) {
	srv, cfgPath := newTestServer(t)
	cfg, err := config.LoadUserConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	session := auth.SetSessionCookie("testsecret", 86400, "alice", auth.SessionRev(cfg.Auth.PasswordHash), false)
	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	setup := auth.SetSetupCookie("bob", secret, "testsecret", 300, false)

	form := url.Values{"code": {"123456"}}
	req := httptest.NewRequest("POST", "/2fa/setup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", session+"; "+setup)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for another user's setup token", rec.Code)
	}
	after, err := config.LoadUserConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if after.Auth.TOTPSecret != "" {
		t.Fatalf("cross-user setup token enrolled a TOTP secret: %q", after.Auth.TOTPSecret)
	}
}

// A pending 2FA token is bound to the password-hash revision. After a password
// change, an in-flight password step must not be able to complete the login.
func TestTwoFARejectsPendingTokenAfterPasswordChange(t *testing.T) {
	srv, _ := newTestServer(t)
	token := auth.CreatePendingToken("alice", "testsecret", 300, "stale-revision")

	req := httptest.NewRequest("GET", "/login/2fa", nil)
	req.Header.Set("Cookie", auth.TOTACookieName+"="+token)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/login" {
		t.Fatalf("stale pending token: status=%d location=%q, want 302 /login", rec.Code, rec.Header().Get("Location"))
	}
}

// Path mode must not reveal another user's service via a 403: vhost mode
// already hides them with 404, so use the same response here.
func TestProxyOtherUserPathReturns404(t *testing.T) {
	srv, cfgPath := newTestServer(t)
	configDir := filepath.Dir(filepath.Dir(cfgPath))
	bobPath := config.UserConfigPath(configDir, "bob")
	bobCfg := "auth:\n  password_hash: \"" + strings.Repeat("2", 64) + "\"\nservices:\n  - id: svc\n    name: Svc\n    host: 127.0.0.1\n    port: 1\n    path: /svc\n"
	if err := os.WriteFile(bobPath, []byte(bobCfg), 0600); err != nil {
		t.Fatal(err)
	}
	aliceCfg, err := config.LoadUserConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cookie := auth.SetSessionCookie("testsecret", 86400, "alice", auth.SessionRev(aliceCfg.Auth.PasswordHash), false)

	req := httptest.NewRequest("GET", "/proxy/bob/svc", nil)
	req.Header.Set("Cookie", cookie)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for another user's path", rec.Code)
	}
}

// Logout must not be triggerable from another origin via a link/image or a
// cross-site POST (logout CSRF). Same-origin and no-Referer requests still work.
func TestLogoutRejectsCrossOriginRequests(t *testing.T) {
	srv, _ := newTestServer(t)

	req := httptest.NewRequest("GET", "/logout", nil)
	req.Host = "gw:30152"
	req.Header.Set("Referer", "http://evil.example/")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-host Referer: status = %d, want 403", rec.Code)
	}

	req = httptest.NewRequest("POST", "/logout", nil)
	req.Host = "gw:30152"
	req.Header.Set("Origin", "http://evil.example")
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-origin POST: status = %d, want 403", rec.Code)
	}
}

// After logout, a bookmarked page-like bare path should lead to login, not a
// bare 404. Asset-looking paths keep 404 so static misses are not masked.
func TestUnauthenticatedBarePageRedirectsToLogin(t *testing.T) {
	srv, _ := newTestServer(t)

	req := httptest.NewRequest("GET", "/dashboard", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "/login?next=") {
		t.Fatalf("page path: status=%d location=%q, want login redirect", rec.Code, rec.Header().Get("Location"))
	}

	req = httptest.NewRequest("GET", "/assets/app.js", nil)
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("asset path: status=%d, want 404", rec.Code)
	}
}
