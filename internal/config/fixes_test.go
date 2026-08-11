package config

import (
	"strings"
	"testing"
)

func TestIsValidPasswordHash(t *testing.T) {
	if !IsValidPasswordHash(HashPassword("pw")) { // bcrypt
		t.Fatal("bcrypt hash must be valid")
	}
	if !IsValidPasswordHash(strings.Repeat("a", 64)) { // legacy SHA-256 hex
		t.Fatal("64-char hex hash must be valid")
	}
	if !IsValidPasswordHash(strings.ToUpper(strings.Repeat("a", 64))) { // uppercase hex ok
		t.Fatal("uppercase hex hash must be valid")
	}
	if IsValidPasswordHash("$2a$10$broken") {
		t.Fatal("malformed bcrypt must be invalid")
	}
	if IsValidPasswordHash("not-a-hash") {
		t.Fatal("garbage must be invalid")
	}
	if IsValidPasswordHash("") {
		t.Fatal("empty must be invalid")
	}
}

// LoadUserConfig must keep a valid bcrypt hash untouched (case-sensitive!)
// and lock accounts with an invalid hash.
func TestLoadUserConfigBcryptHash(t *testing.T) {
	path := newTestConfig(t)
	hash := HashPassword("pw")
	raw, err := loadRawConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	auth, _ := raw["auth"].(map[string]interface{})
	auth["password_hash"] = hash
	raw["auth"] = auth
	if err := saveRawConfig(path, raw); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadUserConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Auth.PasswordHash != hash {
		t.Fatalf("bcrypt hash must be preserved exactly, got %q", cfg.Auth.PasswordHash)
	}

	// Invalid hash -> locked placeholder.
	auth["password_hash"] = "garbage"
	if err := saveRawConfig(path, raw); err != nil {
		t.Fatal(err)
	}
	cfg, err = LoadUserConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Auth.PasswordHash) != 64 {
		t.Fatalf("invalid hash must be replaced with placeholder, got %q", cfg.Auth.PasswordHash)
	}
}

// Hostnames that resolve entirely to private addresses must be accepted.
// "localhost" style names and unresolvable names follow deny-by-default.
func TestIsPrivateOrLocalHostname(t *testing.T) {
	if !IsPrivateOrLocal("localhost") {
		t.Fatal("localhost must be allowed")
	}
	if !IsPrivateOrLocal("127.0.0.1") {
		t.Fatal("127.0.0.1 must be allowed")
	}
	if !IsPrivateOrLocal("10.1.2.3") {
		t.Fatal("10.x must be allowed")
	}
	if IsPrivateOrLocal("8.8.8.8") {
		t.Fatal("public IP must be rejected")
	}
	if IsPrivateOrLocal("example.com") {
		t.Fatal("public hostname must be rejected")
	}
	// Unresolvable hostname must be rejected, not panic.
	if IsPrivateOrLocal("no-such-host.invalid") {
		t.Fatal("unresolvable hostname must be rejected")
	}
}
