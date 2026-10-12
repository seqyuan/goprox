package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/seqyuan/goprox/internal/config"
)

func parseCookie(t *testing.T, raw string) *http.Cookie {
	t.Helper()
	c, err := http.ParseSetCookie(raw)
	if err != nil {
		t.Fatalf("ParseSetCookie(%q): %v", raw, err)
	}
	return c
}

// Over plain HTTP the backend's Domain must go (it does not match the gateway),
// Path must be scoped under the service prefix, and Secure must be cleared so
// the browser actually stores the cookie.
func TestRewriteSetCookieHTTP(t *testing.T) {
	raw := "sid=abc; Domain=127.0.0.1; Path=/; Secure; HttpOnly; SameSite=Strict"
	c := parseCookie(t, RewriteSetCookie(raw, "/proxy/alice/dsh/", false))

	if c.Name != "sid" || c.Value != "abc" {
		t.Fatalf("name/value = %q/%q", c.Name, c.Value)
	}
	if c.Domain != "" {
		t.Fatalf("Domain = %q, want dropped", c.Domain)
	}
	if c.Path != "/proxy/alice/dsh/" {
		t.Fatalf("Path = %q, want /proxy/alice/dsh/", c.Path)
	}
	if c.Secure {
		t.Fatal("Secure must be cleared over HTTP or the cookie is dropped")
	}
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("HttpOnly/SameSite must be preserved: %v/%v", c.HttpOnly, c.SameSite)
	}
}

// Over HTTPS the Secure flag is meaningful and must survive.
func TestRewriteSetCookieHTTPSKeepsSecure(t *testing.T) {
	raw := "sid=abc; Path=/; Secure; HttpOnly"
	c := parseCookie(t, RewriteSetCookie(raw, "/proxy/alice/dsh/", true))
	if !c.Secure {
		t.Fatal("Secure must be preserved when the client is on HTTPS")
	}
	if c.Path != "/proxy/alice/dsh/" {
		t.Fatalf("Path = %q", c.Path)
	}
}

// A backend sub-path cookie is re-rooted beneath the prefix.
func TestRewriteCookiePathSubpath(t *testing.T) {
	c := parseCookie(t, RewriteSetCookie("a=1; Path=/app", "/proxy/alice/svc/", true))
	if c.Path != "/proxy/alice/svc/app" {
		t.Fatalf("Path = %q, want /proxy/alice/svc/app", c.Path)
	}
}

// __Host- requires Secure + Path=/ + no Domain, so once rewritten it must be
// downgraded; __Secure- only loses its prefix when Secure was cleared.
func TestRewriteSetCookieStripsReservedPrefixes(t *testing.T) {
	host := parseCookie(t, RewriteSetCookie("__Host-sid=1; Path=/; Secure", "/proxy/alice/dsh/", true))
	if host.Name != "sid" {
		t.Fatalf("__Host- name = %q, want sid", host.Name)
	}
	secure := parseCookie(t, RewriteSetCookie("__Secure-sid=1; Path=/; Secure", "/proxy/alice/dsh/", false))
	if secure.Name != "sid" {
		t.Fatalf("__Secure- name = %q, want sid over HTTP", secure.Name)
	}
}

// Malformed input is passed through untouched rather than dropped.
func TestRewriteSetCookieMalformedPassThrough(t *testing.T) {
	raw := "this is not a cookie"
	if got := RewriteSetCookie(raw, "/proxy/a/s/", true); got != raw {
		t.Fatalf("got %q, want passthrough %q", got, raw)
	}
}

// Bare/root-path access (referer or default_service routing) must NOT re-root
// Path: the browser is at the gateway root, so narrowing Path to the proxy
// prefix would stop the cookie being sent on subsequent requests. Domain and
// Secure handling still apply.
func TestRewriteSetCookieBarePathKeepsPath(t *testing.T) {
	c := parseCookie(t, RewriteSetCookie("sid=abc; Domain=127.0.0.1; Path=/; Secure", "", true))
	if c.Path != "/" {
		t.Fatalf("Path = %q, want / (untouched)", c.Path)
	}
	if c.Domain != "" {
		t.Fatalf("Domain = %q, want dropped", c.Domain)
	}
	if !c.Secure {
		t.Fatal("Secure must be kept on HTTPS")
	}
}

// A __Host- cookie that still satisfies its invariants (HTTPS, Path=/, no
// Domain) keeps its prefix when we do not re-root the path.
func TestRewriteSetCookieHostPrefixKeptWhenValid(t *testing.T) {
	c := parseCookie(t, RewriteSetCookie("__Host-sid=1; Path=/; Secure", "", true))
	if c.Name != "__Host-sid" {
		t.Fatalf("name = %q, want __Host-sid", c.Name)
	}
}

// End to end through the reverse proxy: a backend Set-Cookie is rewritten.
func TestProxyRewritesBackendSetCookie(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "sid=abc; Domain=127.0.0.1; Path=/; Secure; HttpOnly")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer backend.Close()

	host, port := splitHostPort(backend.Listener.Addr().String())
	svc := &config.ServiceConfig{Host: host, Port: mustAtoi(t, port), Path: "/dsh"}
	req := httptest.NewRequest("GET", "/proxy/alice/dsh/api/x", nil)
	fc := BuildProxyForwardContext(req, "alice", "/dsh", false) // Proto == http
	rp := NewReverseProxy(svc, fc)

	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	vals := rec.Result().Header.Values("Set-Cookie")
	if len(vals) != 1 {
		t.Fatalf("Set-Cookie count = %d, want 1 (%v)", len(vals), vals)
	}
	c := parseCookie(t, vals[0])
	if c.Domain != "" || c.Path != "/proxy/alice/dsh/" || c.Secure {
		t.Fatalf("cookie not rewritten: Domain=%q Path=%q Secure=%v", c.Domain, c.Path, c.Secure)
	}
}

// Bare-path routing must leave the backend cookie Path intact (see above).
func TestProxyLeavesCookiePathForBarePath(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "sid=abc; Path=/; Secure")
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	host, port := splitHostPort(backend.Listener.Addr().String())
	svc := &config.ServiceConfig{Host: host, Port: mustAtoi(t, port), Path: "/web"}
	req := httptest.NewRequest("GET", "/dashboard", nil) // bare path, not under /proxy/
	fc := BuildProxyForwardContext(req, "alice", "/web", false)
	rp := NewReverseProxy(svc, fc)

	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	vals := rec.Result().Header.Values("Set-Cookie")
	if len(vals) != 1 {
		t.Fatalf("Set-Cookie count = %d (%v)", len(vals), vals)
	}
	c := parseCookie(t, vals[0])
	if c.Path != "/" || c.Secure {
		t.Fatalf("bare path cookie: Path=%q Secure=%v (want /, false over HTTP)", c.Path, c.Secure)
	}
}
