package server

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seqyuan/goprox/internal/auth"
	"github.com/seqyuan/goprox/internal/config"
)

// suffixedServer builds a gateway whose cookie names carry the given suffix,
// with one user (alice / "change-me") and no services.
func suffixedServer(t *testing.T, dir, suffix string) *Server {
	t.Helper()
	writeUserYAMLForServer(t, dir, "alice", "services: []\n")
	return New(&config.StateConfig{
		Server: config.ServerState{Host: "127.0.0.1", Port: 30152},
		Auth: config.AuthState{
			SessionSecret: "testsecret",
			SessionTTL:    86400,
			CookieSuffix:  suffix,
		},
	}, dir)
}

func writeUserYAMLForServer(t *testing.T, configDir, username, body string) {
	t.Helper()
	cfgPath := config.UserConfigPath(configDir, username)
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0700); err != nil {
		t.Fatal(err)
	}
	cfg := "auth:\n  password_hash: \"" + auth.HashPassword("change-me") + "\"\n" + body
	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
}

// loginWithClient logs in through h and returns the client (cookie jar keeps
// whatever names the gateway issued).
func loginWithClient(t *testing.T, srv *Server) (*httptest.Server, *http.Client, *http.Response) {
	t.Helper()
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse // keep the 302 so the test can assert it
	}}
	form := url.Values{"username": {"alice"}, "password": {"change-me"}, "next": {"/"}}
	req, _ := http.NewRequest("POST", ts.URL+"/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", ts.URL)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return ts, client, resp
}

func cookieNamed(jar http.CookieJar, rawURL, name string) bool {
	u, _ := url.Parse(rawURL)
	for _, c := range jar.Cookies(u) {
		if c.Name == name {
			return true
		}
	}
	return false
}

// With a suffix, the session cookie must be named accordingly — and the default
// name must not be accepted.
func TestSessionCookieUsesSuffix(t *testing.T) {
	srv := suffixedServer(t, t.TempDir(), "1908")
	ts, client, resp := loginWithClient(t, srv)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login status = %d", resp.StatusCode)
	}
	if !cookieNamed(client.Jar, ts.URL, "goprox_session_1908") {
		t.Fatalf("suffixed session cookie not issued: %v", client.Jar)
	}
	if cookieNamed(client.Jar, ts.URL, "goprox_session") {
		t.Fatal("default-named session cookie was issued alongside the suffixed one")
	}

	// Dashboard stays authenticated with the suffixed cookie.
	res, err := client.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("dashboard status = %d", res.StatusCode)
	}

	// A default-named cookie (e.g. from another instance) must be ignored.
	token := auth.CreateSessionToken("alice", "testsecret", 86400, auth.SessionRev(auth.HashPassword("change-me")))
	req, _ := http.NewRequest("GET", ts.URL+"/", nil)
	req.AddCookie(&http.Cookie{Name: "goprox_session", Value: token})
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK || !strings.Contains(readBody(t, resp2), "login") {
		t.Fatalf("default-named session cookie was accepted (status %d)", resp2.StatusCode)
	}
}

// Logout clears only this instance's cookies: another instance's session cookie
// in the same browser jar must survive.
func TestLogoutClearsOnlyOwnCookies(t *testing.T) {
	srv := suffixedServer(t, t.TempDir(), "1908")
	ts, client, _ := loginWithClient(t, srv)

	u, _ := url.Parse(ts.URL)
	client.Jar.SetCookies(u, []*http.Cookie{
		{Name: "goprox_session_1907", Value: "other-instance", Path: "/"},
		{Name: "goprox_route_1907", Value: "/proxy/alice/x", Path: "/"},
	})

	req, _ := http.NewRequest("POST", ts.URL+"/logout", nil)
	req.Header.Set("Origin", ts.URL)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if cookieNamed(client.Jar, ts.URL, "goprox_session_1908") {
		t.Fatal("own session cookie not cleared")
	}
	if !cookieNamed(client.Jar, ts.URL, "goprox_session_1907") {
		t.Fatal("logout cleared the other instance's session cookie")
	}
	if !cookieNamed(client.Jar, ts.URL, "goprox_route_1907") {
		t.Fatal("logout cleared the other instance's route cookie")
	}
}

// Two gateways on the same host with different suffixes must both stay logged
// in: the browser jar holds both session cookies and each instance reads only
// its own. Before configurable names, the second login overwrote the first.
func TestTwoInstancesOnSameHostStayLoggedIn(t *testing.T) {
	srvA := suffixedServer(t, t.TempDir(), "a")
	srvB := suffixedServer(t, t.TempDir(), "b")

	tsA := httptest.NewServer(srvA.Handler())
	defer tsA.Close()
	tsB := httptest.NewServer(srvB.Handler())
	defer tsB.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	login := func(base string) {
		form := url.Values{"username": {"alice"}, "password": {"change-me"}, "next": {"/"}}
		req, _ := http.NewRequest("POST", base+"/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", base)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("login to %s: %d", base, resp.StatusCode)
		}
	}
	login(tsA.URL)
	login(tsB.URL)

	// Both cookies coexist in one jar (same host, different ports).
	if !cookieNamed(jar, tsA.URL, "goprox_session_a") || !cookieNamed(jar, tsA.URL, "goprox_session_b") {
		t.Fatalf("expected both suffixed cookies in the jar: %v", jar)
	}

	for _, ts := range []*httptest.Server{tsA, tsB} {
		resp, err := client.Get(ts.URL + "/")
		if err != nil {
			t.Fatal(err)
		}
		body := readBody(t, resp)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !strings.Contains(body, "alice") {
			t.Fatalf("instance %s lost its session (status %d)", ts.URL, resp.StatusCode)
		}
	}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return b.String()
}

// The pending-2FA cookie must use the instance suffix too, otherwise two
// instances on one host would overwrite each other mid-login.
func TestPendingTwoFACookieUsesSuffix(t *testing.T) {
	dir := t.TempDir()
	writeUserYAMLForServer(t, dir, "alice", "  totp_secret: \"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\"\nservices: []\n")
	srv := New(&config.StateConfig{
		Server: config.ServerState{Host: "127.0.0.1", Port: 30152},
		Auth:   config.AuthState{SessionSecret: "testsecret", SessionTTL: 86400, CookieSuffix: "1908"},
	}, dir)

	ts, client, resp := loginWithClient(t, srv)
	if resp.StatusCode != http.StatusFound || !strings.Contains(resp.Header.Get("Location"), "/login/2fa") {
		t.Fatalf("expected 2FA redirect, got %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if !cookieNamed(client.Jar, ts.URL, "goprox_2fa_1908") {
		t.Fatalf("pending 2FA cookie not suffixed: %v", client.Jar.Cookies(mustURL(t, ts.URL)))
	}
	if cookieNamed(client.Jar, ts.URL, "goprox_2fa") {
		t.Fatal("default-named pending 2FA cookie was issued")
	}

	// The 2FA form must be reachable with the suffixed pending cookie.
	res, err := client.Get(ts.URL + "/login/2fa")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("2FA page status = %d", res.StatusCode)
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
