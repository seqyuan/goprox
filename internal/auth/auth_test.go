package auth

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetRouteCookieForRequestSkipsDashboardRoot(t *testing.T) {
	cookie := SetRouteCookie("/proxy/alice/tensorboard")
	if got := GetRouteCookieForRequest(cookie, "/", ""); got != "" {
		t.Fatalf("expected dashboard root not to route via cookie, got %q", got)
	}
}

func TestGetRouteCookieForRequestUsesRefererToDisambiguate(t *testing.T) {
	jupyter := SetRouteCookie("/proxy/alice/jupyter")
	tensorboard := SetRouteCookie("/proxy/alice/tensorboard")
	cookie := jupyter + "; " + tensorboard

	got := GetRouteCookieForRequest(cookie, "/api/contents", "http://host/proxy/alice/jupyter/lab")
	if got != "/proxy/alice/jupyter" {
		t.Fatalf("expected referer route, got %q", got)
	}
}

func TestGetRouteCookieForRequestRejectsAmbiguousCookies(t *testing.T) {
	jupyter := SetRouteCookie("/proxy/alice/jupyter")
	tensorboard := SetRouteCookie("/proxy/alice/tensorboard")
	cookie := jupyter + "; " + tensorboard

	if got := GetRouteCookieForRequest(cookie, "/api/contents", ""); got != "" {
		t.Fatalf("expected ambiguous cookies without a recent marker to be ignored, got %q", got)
	}
}

// With a global "most recent service" cookie present, ambiguous bare requests
// (absolute-path asset with no Referer) fall back to the recent service rather
// than returning "" and 404ing the page.
func TestGetRouteCookieForRequestFallsBackToRecentCookie(t *testing.T) {
	jupyter := SetRouteCookie("/proxy/alice/jupyter")
	recent := SetRouteCookies("/proxy/alice/tensorboard")
	cookie := jupyter + "; " + strings.Join(recent, "; ")

	if got := GetRouteCookieForRequest(cookie, "/_next/static/x.js", ""); got != "/proxy/alice/tensorboard" {
		t.Fatalf("expected fallback to most recent route, got %q", got)
	}
}

func TestSetRouteCookiesIncludesGlobalRecent(t *testing.T) {
	cookies := SetRouteCookies("/proxy/alice/jupyter")
	if len(cookies) != 2 {
		t.Fatalf("expected 2 Set-Cookie values, got %d: %v", len(cookies), cookies)
	}
	if !strings.Contains(cookies[1], RouteCookieName+"=/proxy/alice/jupyter") {
		t.Fatalf("global recent cookie missing: %v", cookies)
	}
}

func TestGetRouteCookieForRequestAllowsSingleCookieFallback(t *testing.T) {
	cookie := SetRouteCookie("/proxy/alice/jupyter")
	got := GetRouteCookieForRequest(cookie, "/api/contents", "")
	if got != "/proxy/alice/jupyter" {
		t.Fatalf("expected single cookie fallback, got %q", got)
	}
}

// Changing the password-hash revision must invalidate previously-issued
// session tokens, so a stolen session dies when the password is reset.
func TestSessionRevInvalidatesOldTokens(t *testing.T) {
	token := CreateSessionToken("alice", "secret", 3600, SessionRev("hash-A"))

	if got := ValidateSessionToken(token, "secret", SessionRev("hash-A")); !got.Valid || got.UserID != "alice" {
		t.Fatalf("token must validate against its own revision: %+v", got)
	}
	if got := ValidateSessionToken(token, "secret", SessionRev("hash-B")); got.Valid {
		t.Fatal("token must be invalid after the password-hash revision changes")
	}
	if got := ValidateSessionToken(token, "wrong-secret", SessionRev("hash-A")); got.Valid {
		t.Fatal("token must be invalid with the wrong secret")
	}
}

func TestSameOriginRequest(t *testing.T) {
	cases := []struct {
		name   string
		origin string
		host   string
		want   bool
	}{
		{"no origin (curl/script)", "", "gw:30152", true},
		{"same origin", "http://gw:30152", "gw:30152", true},
		{"same origin case-insensitive host", "http://GW:30152", "gw:30152", true},
		{"https browser behind proxy", "https://gw:443", "gw:443", true},
		{"cross site", "http://evil.example", "gw:30152", false},
		{"cross host same scheme", "http://other:30152", "gw:30152", false},
		{"cross site same host different port", "http://gw:9999", "gw:30152", false},
		{"null origin (sandboxed iframe)", "null", "gw:30152", false},
		{"malformed", "http://", "gw:30152", false},
		{"non-http scheme", "ftp://gw:30152", "gw:30152", false},
	}
	for _, c := range cases {
		req := httptest.NewRequest("POST", "http://"+c.host+"/x", nil)
		if c.origin != "" {
			req.Header.Set("Origin", c.origin)
		}
		if got := SameOriginRequest(req); got != c.want {
			t.Errorf("%s: SameOriginRequest = %v, want %v", c.name, got, c.want)
		}
	}
}
