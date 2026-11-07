package auth

import (
	"strings"
	"testing"
)

func TestCookieNamesDefaultAndSuffix(t *testing.T) {
	def := DefaultCookieNames()
	if def.Session() != SessionCookieName || def.Route() != RouteCookieName ||
		def.TOTAPending() != TOTACookieName || def.TOTASetup() != TOTASetupCookie {
		t.Fatalf("default names changed: %+v", def)
	}
	if def.RoutePrefix() != RouteCookiePrefix {
		t.Fatalf("default route prefix = %q, want %q", def.RoutePrefix(), RouteCookiePrefix)
	}

	n := CookieNamesForSuffix("1908")
	cases := map[string]string{
		"session": n.Session(), "2fa": n.TOTAPending(), "setup": n.TOTASetup(),
		"route": n.Route(), "route-prefix": n.RoutePrefix(),
	}
	want := map[string]string{
		"session": "goprox_session_1908", "2fa": "goprox_2fa_1908",
		"setup": "goprox_2fa_setup_1908", "route": "goprox_route_1908",
		"route-prefix": "goprox_route_1908_",
	}
	for k, got := range cases {
		if got != want[k] {
			t.Errorf("%s = %q, want %q", k, got, want[k])
		}
	}
}

func TestCookieNamesForSuffixTrimsSpace(t *testing.T) {
	if got := CookieNamesForSuffix("  1908 "); got.Session() != "goprox_session_1908" {
		t.Fatalf("suffix not trimmed: %q", got.Session())
	}
}

func TestSuffixedSessionCookieHeader(t *testing.T) {
	n := CookieNamesForSuffix("1908")
	header := n.SetSessionCookie("secret", 60, "alice", "rev", true)
	if !strings.HasPrefix(header, "goprox_session_1908=") {
		t.Fatalf("session header = %q", header)
	}
	if !strings.Contains(header, "HttpOnly") || !strings.Contains(header, "Secure") {
		t.Fatalf("session header lost flags: %q", header)
	}
	if clear := n.ClearSessionCookie(); !strings.HasPrefix(clear, "goprox_session_1908=;") {
		t.Fatalf("clear header = %q", clear)
	}
}

func TestSuffixedRouteCookiesIsolateInstances(t *testing.T) {
	a := CookieNamesForSuffix("a")
	b := CookieNamesForSuffix("b")
	prefix := "/proxy/alice/jupyter"

	// Set-Cookie headers carry attributes; a Cookie request header does not.
	name := func(setCookie string) string { return setCookie[:strings.Index(setCookie, "=")] }

	headers := a.SetRouteCookies(prefix)
	if len(headers) != 2 {
		t.Fatalf("SetRouteCookies wrote %d cookies, want 2", len(headers))
	}
	for _, h := range headers {
		if !strings.HasPrefix(name(h), "goprox_route_a") {
			t.Errorf("instance a wrote foreign cookie %q", name(h))
		}
	}

	// Cookies of instance b must be invisible to instance a (and vice versa).
	bOnly := name(b.SetRouteCookie(prefix)) + "=" + prefix + "; " + b.Route() + "=" + prefix
	if got := a.RouteForRequest(bOnly, "/foo", ""); got != "" {
		t.Fatalf("instance a read instance b's route cookie: %q", got)
	}
	if got := b.RouteForRequest(bOnly, "/foo", ""); got != prefix {
		t.Fatalf("instance b failed to read its own route cookie: %q", got)
	}

	// Logout clears only this instance's cookies.
	both := bOnly + "; " + name(a.SetRouteCookie(prefix)) + "=" + prefix + "; " + a.Route() + "=" + prefix + "; unrelated=1"
	cleared := a.ClearRouteCookies(both)
	if len(cleared) != 2 {
		t.Fatalf("cleared %d cookies, want 2 (own per-service + own global): %v", len(cleared), cleared)
	}
	for _, c := range cleared {
		if strings.HasPrefix(c, "goprox_route_b") || strings.HasPrefix(c, "unrelated") {
			t.Errorf("logout cleared a foreign cookie: %q", c)
		}
	}
}

// The reserved namespace is suffix-agnostic: a proxied backend must never see any
// instance's gateway cookies.
func TestIsGatewayCookieNameCoversSuffixes(t *testing.T) {
	for _, name := range []string{
		"goprox_session", "goprox_session_1908", "goprox_2fa", "goprox_2fa_setup_x",
		"goprox_route", "goprox_route_1908_abcd1234",
	} {
		if !IsGatewayCookieName(name) {
			t.Errorf("IsGatewayCookieName(%q) = false", name)
		}
	}
	for _, name := range []string{"other", "session", "jupyter-session", "_goprox"} {
		if IsGatewayCookieName(name) {
			t.Errorf("IsGatewayCookieName(%q) = true", name)
		}
	}
}
