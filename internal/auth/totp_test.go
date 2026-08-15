package auth

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// A freshly generated secret must be valid base32 and unique.
func TestGenerateTOTPSecret(t *testing.T) {
	a, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	if a == "" || a == b {
		t.Fatal("secrets must be non-empty and unique")
	}
	// Base32 alphabet (RFC 4648) only.
	for _, c := range a {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", c) {
			t.Fatalf("secret contains invalid base32 char %q", c)
		}
	}
}

// VerifyTOTP must accept a correct code for the current window and reject
// wrong / malformed / short codes.
func TestVerifyTOTP(t *testing.T) {
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // RFC 6238 SHA1 test secret
	now := time.Unix(59, 0)                           // counter = 1

	// Compute the expected code with the same function (self-consistent).
	key, err := base32Decode(secret)
	if err != nil {
		t.Fatal(err)
	}
	expected := totpCode(key, uint64(now.Unix()/30))

	if !VerifyTOTP(secret, expected, now) {
		t.Fatalf("expected code %q to verify", expected)
	}
	if VerifyTOTP(secret, "000000", now) {
		t.Fatal("wrong code must not verify")
	}
	if VerifyTOTP(secret, "12345", now) {
		t.Fatal("short code must not verify")
	}
	if VerifyTOTP(secret, "abcdef", now) {
		t.Fatal("non-numeric code must not verify")
	}
	if VerifyTOTP("not-base32!", expected, now) {
		t.Fatal("invalid secret must not verify")
	}
}

// The pending 2FA token must round-trip and reject tampering / expiry.
func TestPendingToken(t *testing.T) {
	const secret = "session-secret"
	token := CreatePendingToken("alice", secret, 300)
	userID, ok := ValidatePendingToken(token, secret)
	if !ok || userID != "alice" {
		t.Fatalf("pending token round-trip failed: userID=%q ok=%v", userID, ok)
	}

	// Tampered token must fail.
	if _, ok := ValidatePendingToken(token+"x", secret); ok {
		t.Fatal("tampered token must fail")
	}
	// Wrong secret must fail.
	if _, ok := ValidatePendingToken(token, "other"); ok {
		t.Fatal("token signed with wrong secret must fail")
	}
	// Expired token must fail.
	expired := CreatePendingToken("alice", secret, -1)
	if _, ok := ValidatePendingToken(expired, secret); ok {
		t.Fatal("expired token must fail")
	}
}

// The setup token (pending TOTP secret) must round-trip independently of the
// pending login token, so the two flows cannot be confused.
func TestSetupToken(t *testing.T) {
	const secret = "session-secret"
	token := CreateSetupToken("GEZDGNBVGY3TQOJQ", secret, 300)
	got, ok := ValidateSetupToken(token, secret)
	if !ok || got != "GEZDGNBVGY3TQOJQ" {
		t.Fatalf("setup token round-trip failed: got=%q ok=%v", got, ok)
	}

	// A login pending token must NOT validate as a setup token.
	login := CreatePendingToken("GEZDGNBVGY3TQOJQ", secret, 300)
	if _, ok := ValidateSetupToken(login, secret); ok {
		t.Fatal("login pending token must not validate as setup token")
	}
}

func base32Decode(s string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}
