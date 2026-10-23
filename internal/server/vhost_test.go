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

type vhostBackend struct {
	srv  *httptest.Server
	path string
	xfp  string
}

func newVHostBackend(t *testing.T, marker string) *vhostBackend {
	t.Helper()
	b := &vhostBackend{}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.path = r.URL.Path
		b.xfp = r.Header.Get("X-Forwarded-Prefix")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<html><head><title>x</title></head><body>%s</body></html>", marker)
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func writeVHostUser(t *testing.T, configDir, username, svcID, svcPath, hostname, backendHost, backendPort, password string) string {
	t.Helper()
	hash := auth.HashPassword(password)
	cfgPath := config.UserConfigPath(configDir, username)
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0700); err != nil {
		t.Fatal(err)
	}
	cfg := fmt.Sprintf(
		"auth:\n  password_hash: %q\nservices:\n  - id: %s\n    name: %s\n    host: %s\n    port: %s\n    path: %s\n    hostnames:\n      - %s\n    websocket: true\n",
		hash, svcID, svcID, backendHost, backendPort, svcPath, hostname,
	)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	return hash
}

func newVHostServer(t *testing.T, configDir string) *Server {
	t.Helper()
	srv := New(&config.StateConfig{
		Server: config.ServerState{
			Host:         "127.0.0.1",
			Port:         30152,
			PublicHost:   "gw.example.test",
			PublicScheme: "http",
			CookieDomain: ".example.test",
		},
		Auth: config.AuthState{SessionSecret: "testsecret", SessionTTL: 86400},
	}, configDir)
	if err := srv.ValidateVHosts(); err != nil {
		t.Fatalf("ValidateVHosts: %v", err)
	}
	return srv
}

func vhostCookie(user, hash string) string {
	return auth.SetSessionCookieWithDomain("testsecret", 86400, user, auth.SessionRev(hash), false, ".example.test")
}

func vhostRequest(t *testing.T, srv *Server, method, host, path, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Host = host
	// Browser navigation, so unauthenticated requests get the login redirect.
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func TestVHostRoutesToOwnerAtRoot(t *testing.T) {
	backend := newVHostBackend(t, "hugo")
	host, port := backendAddr(t, backend.srv)
	dir := t.TempDir()
	hash := writeVHostUser(t, dir, "alice", "hugo", "/hugo", "hugo.example.test", host, port, "pw")
	srv := newVHostServer(t, dir)

	rec := vhostRequest(t, srv, "GET", "hugo.example.test", "/docs/", vhostCookie("alice", hash))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if backend.path != "/docs/" {
		t.Fatalf("backend path = %q, want /docs/", backend.path)
	}
	if backend.xfp != "" {
		t.Fatalf("X-Forwarded-Prefix = %q, want empty", backend.xfp)
	}
	if !strings.Contains(rec.Body.String(), `<base href="/docs/">`) {
		t.Fatalf("missing vhost base: %s", rec.Body.String())
	}
	if got := rec.Result().Header.Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("vhost request must not set route cookies: %v", got)
	}
}

func TestVHostRedirectsToMainLogin(t *testing.T) {
	backend := newVHostBackend(t, "hugo")
	host, port := backendAddr(t, backend.srv)
	dir := t.TempDir()
	writeVHostUser(t, dir, "alice", "hugo", "/hugo", "hugo.example.test", host, port, "pw")
	srv := newVHostServer(t, dir)

	rec := vhostRequest(t, srv, "GET", "hugo.example.test", "/docs/", "")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	want := "http://gw.example.test/login?next=" + url.QueryEscape("http://hugo.example.test/docs/")
	if got := rec.Header().Get("Location"); got != want {
		t.Fatalf("Location = %q, want %q", got, want)
	}
	if backend.path != "" {
		t.Fatalf("backend must not be reached, got %q", backend.path)
	}
}

func TestVHostRejectsOtherUser(t *testing.T) {
	aliceBackend := newVHostBackend(t, "alice")
	bobBackend := newVHostBackend(t, "bob")
	ah, ap := backendAddr(t, aliceBackend.srv)
	bh, bp := backendAddr(t, bobBackend.srv)
	dir := t.TempDir()
	aliceHash := writeVHostUser(t, dir, "alice", "hugo", "/hugo", "hugo.example.test", ah, ap, "pw")
	writeVHostUser(t, dir, "bob", "bobsvc", "/bobsvc", "bob.example.test", bh, bp, "pw")
	srv := newVHostServer(t, dir)

	rec := vhostRequest(t, srv, "GET", "bob.example.test", "/docs/", vhostCookie("alice", aliceHash))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if bobBackend.path != "" || aliceBackend.path != "" {
		t.Fatalf("backends must not be reached: alice=%q bob=%q", aliceBackend.path, bobBackend.path)
	}
}

func TestVHostUnknownHostFallsBackToPathMux(t *testing.T) {
	backend := newVHostBackend(t, "hugo")
	host, port := backendAddr(t, backend.srv)
	dir := t.TempDir()
	writeVHostUser(t, dir, "alice", "hugo", "/hugo", "hugo.example.test", host, port, "pw")
	srv := newVHostServer(t, dir)

	rec := vhostRequest(t, srv, "GET", "unknown.example.test", "/", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 login page", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "登录") {
		t.Fatalf("unknown host did not fall back to the login page")
	}
}

func TestMainHostBareServiceRedirectUnchanged(t *testing.T) {
	backend := newVHostBackend(t, "hugo")
	host, port := backendAddr(t, backend.srv)
	dir := t.TempDir()
	hash := writeVHostUser(t, dir, "alice", "hugo", "/hugo", "hugo.example.test", host, port, "pw")
	srv := newVHostServer(t, dir)

	rec := vhostRequest(t, srv, "GET", "gw.example.test", "/hugo/docs", vhostCookie("alice", hash))
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "/proxy/alice/hugo/docs" {
		t.Fatalf("Location = %q, want /proxy/alice/hugo/docs", got)
	}
	if backend.path != "" {
		t.Fatalf("backend must not be reached by the redirect, got %q", backend.path)
	}
}

func TestLoginNextAllowsOwnVHostAndSetsDomainCookie(t *testing.T) {
	backend := newVHostBackend(t, "hugo")
	host, port := backendAddr(t, backend.srv)
	dir := t.TempDir()
	writeVHostUser(t, dir, "alice", "hugo", "/hugo", "hugo.example.test", host, port, "pw")
	srv := newVHostServer(t, dir)

	form := url.Values{
		"username": {"alice"},
		"password": {"pw"},
		"next":     {"http://hugo.example.test/docs/"},
	}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Host = "gw.example.test"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://gw.example.test")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "http://hugo.example.test/docs/" {
		t.Fatalf("Location = %q", got)
	}
	cookies := rec.Result().Header.Values("Set-Cookie")
	foundDomain := false
	for _, c := range cookies {
		if strings.Contains(c, "Domain=.example.test") {
			foundDomain = true
		}
	}
	if !foundDomain {
		t.Fatalf("session cookie missing Domain=.example.test: %v", cookies)
	}
}

func TestLoginNextRejectsOtherUsersVHost(t *testing.T) {
	aliceBackend := newVHostBackend(t, "alice")
	bobBackend := newVHostBackend(t, "bob")
	ah, ap := backendAddr(t, aliceBackend.srv)
	bh, bp := backendAddr(t, bobBackend.srv)
	dir := t.TempDir()
	writeVHostUser(t, dir, "alice", "hugo", "/hugo", "hugo.example.test", ah, ap, "pw")
	writeVHostUser(t, dir, "bob", "bobsvc", "/bobsvc", "bob.example.test", bh, bp, "pw")
	srv := newVHostServer(t, dir)

	form := url.Values{
		"username": {"alice"},
		"password": {"pw"},
		"next":     {"http://bob.example.test/"},
	}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Host = "gw.example.test"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://gw.example.test")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "/" {
		t.Fatalf("Location = %q, want /", got)
	}
}

func TestLogoutClearsDomainCookie(t *testing.T) {
	backend := newVHostBackend(t, "hugo")
	host, port := backendAddr(t, backend.srv)
	dir := t.TempDir()
	hash := writeVHostUser(t, dir, "alice", "hugo", "/hugo", "hugo.example.test", host, port, "pw")
	srv := newVHostServer(t, dir)

	reqCookie := vhostCookie("alice", hash) + "; " +
		auth.SetSessionCookie("testsecret", 86400, "alice", auth.SessionRev(hash), false)
	rec := vhostRequest(t, srv, "GET", "gw.example.test", "/logout", reqCookie)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d", rec.Code)
	}
	var domainClear, hostClear, pendingClear, setupClear bool
	for _, c := range rec.Result().Header.Values("Set-Cookie") {
		switch {
		case strings.HasPrefix(c, auth.SessionCookieName+"=;"):
			if strings.Contains(c, "Domain=.example.test") {
				domainClear = true
			} else {
				hostClear = true
			}
		case strings.HasPrefix(c, auth.TOTACookieName+"=;"):
			pendingClear = true
		case strings.HasPrefix(c, auth.TOTASetupCookie+"=;"):
			setupClear = true
		}
		if !strings.Contains(c, "Expires=Thu, 01 Jan 1970") {
			t.Fatalf("clear cookie does not expire immediately: %q", c)
		}
	}
	if !domainClear {
		t.Fatalf("logout did not clear the parent-domain session: %v", rec.Result().Header.Values("Set-Cookie"))
	}
	if !hostClear {
		t.Fatalf("logout did not clear a stale host-only session: %v", rec.Result().Header.Values("Set-Cookie"))
	}
	if !pendingClear || !setupClear {
		t.Fatalf("logout did not clear temporary 2FA cookies: %v", rec.Result().Header.Values("Set-Cookie"))
	}
}

func loginWithNext(t *testing.T, srv *Server, next string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{
		"username": {"alice"},
		"password": {"pw"},
		"next":     {next},
	}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Host = "gw.example.test"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://gw.example.test")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func TestLoginNextRejectsPortAndSchemeSwitch(t *testing.T) {
	backend := newVHostBackend(t, "hugo")
	host, port := backendAddr(t, backend.srv)
	dir := t.TempDir()
	writeVHostUser(t, dir, "alice", "hugo", "/hugo", "hugo.example.test", host, port, "pw")
	srv := newVHostServer(t, dir)

	for _, next := range []string{
		"http://hugo.example.test:9999/docs/",
		"https://hugo.example.test/docs/",
	} {
		rec := loginWithNext(t, srv, next)
		if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
			t.Errorf("next %q: status=%d location=%q, want /", next, rec.Code, rec.Header().Get("Location"))
		}
	}
}

func TestValidateVHostsRequiresCookieCoverage(t *testing.T) {
	backend := newVHostBackend(t, "hugo")
	host, port := backendAddr(t, backend.srv)
	dir := t.TempDir()
	writeVHostUser(t, dir, "alice", "hugo", "/hugo", "hugo.other.test", host, port, "pw")

	srv := New(&config.StateConfig{
		Server: config.ServerState{
			Host:         "127.0.0.1",
			Port:         30152,
			PublicHost:   "gw.example.test",
			PublicScheme: "http",
			CookieDomain: ".example.test",
		},
		Auth: config.AuthState{SessionSecret: "testsecret", SessionTTL: 86400},
	}, dir)
	if err := srv.ValidateVHosts(); err == nil {
		t.Fatal("ValidateVHosts must reject a service host outside cookie_domain")
	}
}

func TestLoginNextRequiresNonstandardPublicPort(t *testing.T) {
	backend := newVHostBackend(t, "hugo")
	host, port := backendAddr(t, backend.srv)
	dir := t.TempDir()
	writeVHostUser(t, dir, "alice", "hugo", "/hugo", "hugo.example.test", host, port, "pw")
	srv := New(&config.StateConfig{
		Server: config.ServerState{
			Host:         "127.0.0.1",
			Port:         39099,
			PublicHost:   "gw.example.test:39099",
			PublicScheme: "http",
			CookieDomain: ".example.test",
		},
		Auth: config.AuthState{SessionSecret: "testsecret", SessionTTL: 86400},
	}, dir)
	if err := srv.ValidateVHosts(); err != nil {
		t.Fatalf("ValidateVHosts: %v", err)
	}

	post := func(next string) *httptest.ResponseRecorder {
		form := url.Values{
			"username": {"alice"},
			"password": {"pw"},
			"next":     {next},
		}
		req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
		req.Host = "gw.example.test:39099"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "http://gw.example.test:39099")
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}

	withPort := "http://hugo.example.test:39099/docs/"
	if rec := post(withPort); rec.Code != http.StatusFound || rec.Header().Get("Location") != withPort {
		t.Fatalf("with port: status=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := post("http://hugo.example.test/docs/"); rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		t.Fatalf("missing port: status=%d location=%q, want /", rec.Code, rec.Header().Get("Location"))
	}
}

// Unauthenticated API/XHR requests on a vhost must get 401, not a 302 to the
// login HTML page (which fetch clients would try to parse as their own data).
func TestVHostUnauthenticatedAPIReturns401(t *testing.T) {
	backend := newVHostBackend(t, "hugo")
	host, port := backendAddr(t, backend.srv)
	dir := t.TempDir()
	writeVHostUser(t, dir, "alice", "hugo", "/hugo", "hugo.example.test", host, port, "pw")
	srv := newVHostServer(t, dir)

	req := httptest.NewRequest("GET", "/api/data", nil)
	req.Host = "hugo.example.test"
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Location") != "" {
		t.Fatalf("API request must not be redirected to login: %q", rec.Header().Get("Location"))
	}
	if backend.path != "" {
		t.Fatalf("backend must not be reached, got %q", backend.path)
	}
}
