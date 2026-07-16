package auth

import "testing"

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
		t.Fatalf("expected ambiguous cookies to be ignored, got %q", got)
	}
}

func TestGetRouteCookieForRequestAllowsSingleCookieFallback(t *testing.T) {
	cookie := SetRouteCookie("/proxy/alice/jupyter")
	got := GetRouteCookieForRequest(cookie, "/api/contents", "")
	if got != "/proxy/alice/jupyter" {
		t.Fatalf("expected single cookie fallback, got %q", got)
	}
}
