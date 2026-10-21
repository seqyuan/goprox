package auth

import (
	"strings"
	"testing"
)

func TestSetSessionCookieWithDomain(t *testing.T) {
	cookie := SetSessionCookieWithDomain("secret", 3600, "alice", "rev", true, ".gw.example.com")
	for _, want := range []string{
		SessionCookieName + "=",
		"Path=/",
		"Domain=.gw.example.com",
		"HttpOnly",
		"SameSite=Lax",
		"Secure",
	} {
		if !strings.Contains(cookie, want) {
			t.Fatalf("cookie %q missing %q", cookie, want)
		}
	}
}

func TestSetSessionCookieWithoutDomain(t *testing.T) {
	cookie := SetSessionCookie("secret", 3600, "alice", "rev", false)
	if strings.Contains(cookie, "Domain=") {
		t.Fatalf("host-only cookie must not contain Domain: %q", cookie)
	}
}

func TestClearSessionCookieWithDomain(t *testing.T) {
	cookie := ClearSessionCookieWithDomain(".gw.example.com")
	for _, want := range []string{SessionCookieName + "=", "Domain=.gw.example.com", "Expires=Thu, 01 Jan 1970"} {
		if !strings.Contains(cookie, want) {
			t.Fatalf("clear cookie %q missing %q", cookie, want)
		}
	}
}
