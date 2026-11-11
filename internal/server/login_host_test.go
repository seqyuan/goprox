package server

// 启用虚拟主机（cookie_domain）后，会话 Cookie 带父域 Domain，浏览器只在域内
// 保存它。用 IP 或其他域名访问时必须明确报错，否则表现为"登录成功后又回到登录页"。

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/seqyuan/goprox/internal/auth"
	"github.com/seqyuan/goprox/internal/config"
)

// writeUserWithPassword creates a user config with a bcrypt password.
func writeUserWithPassword(cfgPath, password string) error {
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0700); err != nil {
		return err
	}
	cfg := "auth:\n  password_hash: \"" + auth.HashPassword(password) + "\"\nservices: []\n"
	return os.WriteFile(cfgPath, []byte(cfg), 0600)
}

// aliceCookieForServer mints a valid session cookie for alice in srv's config.
func aliceCookieForServer(t *testing.T, srv *Server) string {
	t.Helper()
	uc := srv.registry.GetUserConfigForLogin("alice")
	if uc == nil {
		t.Fatal("alice not loaded")
	}
	return auth.SetSessionCookie("testsecret", 86400, "alice", auth.SessionRev(uc.Auth.PasswordHash), false)
}

var totpSecretRe = regexp.MustCompile(`[A-Z2-7]{32}`)

type setupPageResult struct {
	body        string
	secret      string
	setupCookie string
}

// setupPage fetches the TOTP enrollment page and extracts the rendered secret
// plus the pending setup cookie.
func setupPage(t *testing.T, srv *Server, cookie string) setupPageResult {
	t.Helper()
	req := httptest.NewRequest("GET", "/2fa/setup", nil)
	req.Host = "gw"
	req.Header.Set("Cookie", cookie)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("setup page status = %d", rec.Code)
	}
	out := setupPageResult{body: rec.Body.String()}
	if m := totpSecretRe.FindString(out.body); m != "" {
		out.secret = m
	}
	for _, c := range rec.Header().Values("Set-Cookie") {
		if strings.HasPrefix(c, auth.TOTASetupCookie+"=") {
			out.setupCookie = strings.SplitN(c, ";", 2)[0]
		}
	}
	return out
}

// vhostServer builds a gateway configured the way a virtual-host deployment is:
// a parent cookie domain plus the main public authority inside it.
func vhostServer(t *testing.T) *Server {
	t.Helper()
	configDir := t.TempDir()
	cfgPath := config.UserConfigPath(configDir, "alice")
	if err := writeUserWithPassword(cfgPath, "pw"); err != nil {
		t.Fatal(err)
	}
	return New(&config.StateConfig{
		Server: config.ServerState{
			Host:         "127.0.0.1",
			Port:         30152,
			PublicHost:   "gw.lab.test",
			CookieDomain: ".lab.test",
		},
		Auth: config.AuthState{SessionSecret: "testsecret", SessionTTL: 86400},
	}, configDir)
}

func loginForm(t *testing.T, srv *Server, host, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"username": {username}, "password": {password}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = host
	req.Header.Set("Origin", "http://"+host)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

// A login on an authority outside cookie_domain must fail loudly: the session
// cookie would be rejected by the browser, so "success" would just bounce the
// user back to the login page with no explanation.
func TestLoginRefusedOutsideCookieDomain(t *testing.T) {
	srv := vhostServer(t)

	rec := loginForm(t, srv, "192.168.0.7:30152", "alice", "pw")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if got := rec.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("issued cookies for an out-of-domain login: %v", got)
	}
	body := rec.Body.String()
	for _, want := range []string{".lab.test", "192.168.0.7", "gw.lab.test"} {
		if !strings.Contains(body, want) {
			t.Errorf("login page does not explain the problem (%q missing): %s", want, body)
		}
	}

	// GET /login on the same authority shows the explanation instead of a form
	// that cannot possibly produce a usable session.
	req := httptest.NewRequest("GET", "/login", nil)
	req.Host = "192.168.0.7:30152"
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), ".lab.test") {
		t.Fatalf("GET /login status=%d body=%s", rec.Code, rec.Body.String())
	}
}

// Inside cookie_domain nothing changes: the login succeeds and the cookie is
// scoped to the parent domain (that is what makes service subdomains work).
func TestLoginInsideCookieDomainStillWorks(t *testing.T) {
	srv := vhostServer(t)

	rec := loginForm(t, srv, "gw.lab.test", "alice", "pw")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 (body=%s)", rec.Code, rec.Body.String())
	}
	var session string
	for _, c := range rec.Header().Values("Set-Cookie") {
		if strings.HasPrefix(c, auth.SessionCookieName+"=") && strings.Contains(c, "Domain=.lab.test") {
			session = c
		}
	}
	if session == "" {
		t.Fatalf("no domain-scoped session cookie: %v", rec.Header().Values("Set-Cookie"))
	}

	// The issued session must be usable on a service subdomain.
	token := strings.SplitN(strings.TrimPrefix(session, auth.SessionCookieName+"="), ";", 2)[0]
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "gw.lab.test"
	req.Header.Set("Cookie", auth.SessionCookieName+"="+token)
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "alice") {
		t.Fatalf("session not accepted on the gateway host: %d", rec.Code)
	}
}

// Without cookie_domain the guard must stay out of the way (plain LAN / IP
// deployments are the default).
func TestLoginAllowedWithoutCookieDomain(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := loginForm(t, srv, "192.168.0.7:30152", "alice", "pw")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
}

// Refreshing the enrollment page (or opening it in a second tab) must keep the
// same pending secret, otherwise the QR code the user is scanning stops
// matching and every correct code is rejected.
func TestTwoFASetupReusesPendingSecret(t *testing.T) {
	srv, _ := newTestServer(t)
	cookie := aliceCookieForServer(t, srv)

	first := setupPage(t, srv, cookie)
	secret1 := first.secret
	if secret1 == "" {
		t.Fatalf("no secret rendered: %s", first.body)
	}
	if first.setupCookie == "" {
		t.Fatal("no setup cookie issued")
	}

	second := setupPage(t, srv, cookie+"; "+first.setupCookie)
	if second.secret != secret1 {
		t.Fatalf("secret rotated on refresh: %q -> %q", secret1, second.secret)
	}
}
