package config

import (
	"context"
	"net"
	"os"
	"path/filepath"
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

// Link-local addresses (including cloud metadata 169.254.169.254) must be
// rejected even though they are not publicly routable; allowing them would let
// a gateway user proxy to the instance metadata service and read credentials.
func TestPrivateIPRejectsLinkLocalAndMetadata(t *testing.T) {
	rejected := []string{
		"169.254.169.254",
		"169.254.0.0",
		"fe80::1",
		"::ffff:169.254.169.254",
		"ff02::1",
		"8.8.8.8",
	}
	for _, h := range rejected {
		if IsPrivateOrLocal(h) {
			t.Errorf("IsPrivateOrLocal(%q) = true, want false", h)
		}
	}

	allowed := []string{"127.0.0.1", "::1", "10.1.2.3", "192.168.1.1", "172.16.0.1", "fd00::1"}
	for _, h := range allowed {
		if !IsPrivateOrLocal(h) {
			t.Errorf("IsPrivateOrLocal(%q) = false, want true", h)
		}
	}
}

// IsTrustedProxyTooBroad flags ranges that would let any client spoof
// X-Forwarded-* headers.
func TestIsTrustedProxyTooBroad(t *testing.T) {
	if !IsTrustedProxyTooBroad("0.0.0.0/0") {
		t.Fatal("0.0.0.0/0 must be reported as too broad")
	}
	if !IsTrustedProxyTooBroad("::/0") {
		t.Fatal("::/0 must be reported as too broad")
	}
	if IsTrustedProxyTooBroad("127.0.0.1/32") {
		t.Fatal("127.0.0.1/32 must not be too broad")
	}
	if IsTrustedProxyTooBroad("10.0.0.0/8") {
		t.Fatal("10.0.0.0/8 must not be too broad")
	}
	if IsTrustedProxyTooBroad("") {
		t.Fatal("empty must not be too broad")
	}
}

// SafeDialContext must refuse public and link-local destinations and dial a
// validated loopback listener directly.
func TestSafeDialContext(t *testing.T) {
	if _, err := SafeDialContext(context.Background(), "tcp", "8.8.8.8:80"); err == nil {
		t.Fatal("expected public IP to be rejected")
	}
	if _, err := SafeDialContext(context.Background(), "tcp", "169.254.169.254:80"); err == nil {
		t.Fatal("expected link-local metadata IP to be rejected")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	if _, err := SafeDialContext(context.Background(), "tcp", ln.Addr().String()); err != nil {
		t.Fatalf("expected local dial to succeed, got %v", err)
	}
}


func TestLoadUserConfigDefaultServiceValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "alice.yaml")
	cfgText := "auth:\n  password_hash: \"1111111111111111111111111111111111111111111111111111111111111111\"\ndefault_service: web\nservices:\n  - id: web\n    name: Web\n    host: 127.0.0.1\n    port: 8080\n    path: /web\n"
	os.WriteFile(path, []byte(cfgText), 0600)
	cfg, err := LoadUserConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DefaultService != "web" {
		t.Fatalf("DefaultService = %q, want web", cfg.DefaultService)
	}
}

func TestLoadUserConfigDefaultServiceInvalidDropped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "alice.yaml")
	cfgText := "auth:\n  password_hash: \"1111111111111111111111111111111111111111111111111111111111111111\"\ndefault_service: nope\nservices:\n  - id: web\n    name: Web\n    host: 127.0.0.1\n    port: 8080\n    path: /web\n"
	os.WriteFile(path, []byte(cfgText), 0600)
	cfg, err := LoadUserConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DefaultService != "" {
		t.Fatalf("stale DefaultService should be dropped, got %q", cfg.DefaultService)
	}
}
