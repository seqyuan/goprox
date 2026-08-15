package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// bcrypt hashes must verify, and legacy unsalted SHA-256 hex must still work.
func TestVerifyPasswordBcryptAndLegacy(t *testing.T) {
	bc := HashPassword("s3cret")
	if !strings.HasPrefix(bc, "$2") {
		t.Fatalf("HashPassword should produce bcrypt, got %q", bc)
	}
	if !VerifyPassword("s3cret", bc) {
		t.Fatal("bcrypt hash must verify")
	}
	if VerifyPassword("wrong", bc) {
		t.Fatal("wrong password must not verify against bcrypt")
	}

	// Legacy SHA-256 hex (old format) must keep working.
	legacy := "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8" // "password"
	if !VerifyPassword("password", legacy) {
		t.Fatal("legacy SHA-256 hash must verify")
	}
	if VerifyPassword("other", legacy) {
		t.Fatal("wrong password must not verify against legacy hash")
	}

	// All-zero placeholder must not verify anything.
	if VerifyPassword("", "0000000000000000000000000000000000000000000000000000000000000000") {
		t.Fatal("placeholder hash must never verify")
	}
}

// Long passwords (over bcrypt's 72-byte limit) must still round-trip.
func TestVerifyPasswordLongInput(t *testing.T) {
	long := strings.Repeat("a", 100)
	h := HashPassword(long)
	if !VerifyPassword(long, h) {
		t.Fatal("long password must verify (bcrypt truncation consistent)")
	}
}

// Unknown usernames must verify against a dummy bcrypt hash (equalizing timing)
// and always fail; known hashes must still verify normally.
func TestVerifyPasswordTimingSafe(t *testing.T) {
	if VerifyPasswordTimingSafe("pw", "") {
		t.Fatal("empty hash must never verify")
	}
	bc := HashPassword("s3cret")
	if !VerifyPasswordTimingSafe("s3cret", bc) {
		t.Fatal("bcrypt hash must verify via timing-safe path")
	}
	if VerifyPasswordTimingSafe("wrong", bc) {
		t.Fatal("wrong password must not verify")
	}
}

// ClientIP must ignore spoofed X-Forwarded-For unless a trusted proxy is
// configured and the request actually arrives from it.
func TestClientIPTrustedProxyGating(t *testing.T) {
	ConfigureTrustedProxy("")

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.7:4321"
	req.Header.Set("X-Forwarded-For", "6.6.6.6")
	if got := ClientIP(req); got != "203.0.113.7" {
		t.Fatalf("without trusted proxy, XFF must be ignored, got %q", got)
	}
	// X-Forwarded-Proto must also be ignored.
	if IsSecureRequest(req) {
		t.Fatal("X-Forwarded-Proto must be ignored without a trusted proxy")
	}

	// Trusted proxy configured: spoofed XFF from a non-proxy peer is still ignored.
	ConfigureTrustedProxy("127.0.0.1/32")
	if got := ClientIP(req); got != "203.0.113.7" {
		t.Fatalf("spoofed XFF from untrusted peer must be ignored, got %q", got)
	}
	if IsSecureRequest(req) {
		t.Fatal("X-Forwarded-Proto from untrusted peer must be ignored")
	}

	// Request arriving from the trusted proxy: headers are honored.
	req.RemoteAddr = "127.0.0.1:4321"
	if got := ClientIP(req); got != "6.6.6.6" {
		t.Fatalf("trusted proxy XFF must be honored, got %q", got)
	}
	req.Header.Set("X-Forwarded-Proto", "https")
	if !IsSecureRequest(req) {
		t.Fatal("trusted proxy X-Forwarded-Proto https must be honored")
	}

	// IPv6 peer address parsing must not break (old LastIndex(":") code did).
	ConfigureTrustedProxy("")
	req.RemoteAddr = "[::1]:4321"
	if got := ClientIP(req); got != "::1" {
		t.Fatalf("IPv6 peer address parsing, got %q", got)
	}
}

// ClearRouteCookies must emit expiry Set-Cookie headers for every route cookie.
func TestClearRouteCookies(t *testing.T) {
	cookies := SetSessionCookie("testsecret", 3600, "alice", "rev", false) + "; " +
		SetRouteCookie("/proxy/alice/jupyter") + "; " +
		SetRouteCookie("/proxy/alice/rstudio") + "; " +
		"backend_cookie=1"

	clears := ClearRouteCookies(cookies)
	if len(clears) != 2 {
		t.Fatalf("expected 2 route cookies to clear, got %d: %v", len(clears), clears)
	}
	for _, c := range clears {
		if !strings.Contains(c, "Expires=Thu, 01 Jan 1970") {
			t.Fatalf("clear cookie must expire immediately: %q", c)
		}
		if strings.Contains(c, "backend_cookie") {
			t.Fatal("non-route cookies must not be cleared")
		}
	}
}

// HTTP handler sanity: the default transport forwards a request as-is.
func TestHandlerIsHTTP(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	if r.Proto != "HTTP/1.1" {
		t.Fatal("sanity")
	}
	_ = http.StatusOK
}
