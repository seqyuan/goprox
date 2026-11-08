package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestLoadStatePersistsGeneratedSessionSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), StateFile)

	state, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if state.Auth.SessionSecret == "" {
		t.Fatal("generated session secret is empty")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted state: %v", err)
	}
	var persisted StateConfig
	if err := yaml.Unmarshal(data, &persisted); err != nil {
		t.Fatalf("parse persisted state: %v", err)
	}
	if persisted.Auth.SessionSecret != state.Auth.SessionSecret {
		t.Fatalf("persisted secret %q != returned secret %q", persisted.Auth.SessionSecret, state.Auth.SessionSecret)
	}

	// A restart must reuse the persisted secret instead of rotating it.
	reloaded, err := LoadState(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Auth.SessionSecret != state.Auth.SessionSecret {
		t.Fatalf("secret rotated across reload: %q != %q", reloaded.Auth.SessionSecret, state.Auth.SessionSecret)
	}
}

// If the generated secret cannot be persisted, startup must fail instead of
// silently rotating the secret (and logging every user out) on each restart.
func TestLoadStateFailsWhenGeneratedSecretCannotBePersisted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, StateFile)
	// Valid state without a secret, but read-only so WriteFile fails.
	if err := os.WriteFile(path, []byte("server:\n  host: 127.0.0.1\n  port: 30152\nauth:\n  session_ttl: 60\n"), 0o400); err != nil {
		t.Fatal(err)
	}

	_, err := LoadState(path)
	if err == nil {
		// Root (or a filesystem that ignores permission bits) can write the
		// file anyway; the failure path cannot be exercised in that case.
		t.Skip("file permissions are not enforced; skipping read-only test")
	}
	if !strings.Contains(err.Error(), "persist generated session_secret") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestIsValidHeaderName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"", false},
		{"X-Authenticated-User", true},
		{"Remote_User", true},
		{"X-Custom-User", true},
		{"a.b-c_d", true},     // token chars: . - _ all legal
		{"Bad Header", false}, // space is not a token char
		{"Header\nInjection", false},
		{"头", false},   // non-ASCII
		{"X:Y", false}, // colon is not a token char
	}
	for _, tc := range cases {
		if got := IsValidHeaderName(tc.name); got != tc.want {
			t.Errorf("IsValidHeaderName(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestPersistServerConfigVHostFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), StateFile)
	if err := EnsureState(path); err != nil {
		t.Fatal(err)
	}
	if err := PersistServerConfig(path, "127.0.0.1", 30152, "", "", "", "",
		"GW.Example.Test:30152", "HTTPS", ".Example.Test"); err != nil {
		t.Fatal(err)
	}
	st, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Server.PublicHost != "gw.example.test:30152" || st.Server.PublicScheme != "https" || st.Server.CookieDomain != ".example.test" {
		t.Fatalf("vhost fields = %+v", st.Server)
	}

	// Empty values preserve the existing fields.
	if err := PersistServerConfig(path, "127.0.0.1", 30152, "", "", "", "", "", "", ""); err != nil {
		t.Fatal(err)
	}
	st, err = LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Server.PublicHost != "gw.example.test:30152" || st.Server.CookieDomain != ".example.test" {
		t.Fatalf("vhost fields were lost: %+v", st.Server)
	}
}

// A hand-edited state with only one half of the TLS pair must fail fast instead
// of silently serving plain HTTP (while public_scheme logic assumes HTTPS).
func TestLoadStateRejectsHalfTLSConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), StateFile)
	raw := "server:\n  host: 127.0.0.1\n  port: 30152\n  tls_cert: /tmp/cert.pem\nauth:\n  session_ttl: 60\n"
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(path); err == nil {
		t.Fatal("LoadState accepted tls_cert without tls_key")
	}
}

// auth.cookie_suffix isolates two goprox instances on the same host; it is
// validated at load time and persisted verbatim (including when the session
// secret is generated on first run).
func TestCookieSuffix(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.yaml")
	body := "server:\n  host: 127.0.0.1\n  port: 30152\nauth:\n  session_secret: \"\"\n  session_ttl: 3600\n  cookie_suffix: \"1908\"\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}

	state, err := LoadState(path) // generates + persists the secret
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if state.Auth.CookieSuffix != "1908" {
		t.Fatalf("cookie_suffix = %q", state.Auth.CookieSuffix)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `cookie_suffix: "1908"`) && !strings.Contains(string(raw), "cookie_suffix: 1908") {
		t.Fatalf("cookie_suffix not persisted:\n%s", raw)
	}

	// Invalid suffixes must fail startup rather than silently fall back.
	for _, bad := range []string{"has space", "with/slash", "abcdefghijklmnopqrstuvwxyz0123456789", "中文"} {
		if err := os.WriteFile(path, []byte("auth:\n  session_secret: \"x\"\n  cookie_suffix: "+bad+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadState(path); err == nil {
			t.Errorf("cookie_suffix %q accepted", bad)
		}
	}
}

func TestNormalizeCookieSuffix(t *testing.T) {
	for _, ok := range []string{"", "1908", "a", "A-b_9", strings.Repeat("x", 32)} {
		got, err := NormalizeCookieSuffix(ok)
		if err != nil || got != strings.TrimSpace(ok) {
			t.Errorf("NormalizeCookieSuffix(%q) = %q, %v", ok, got, err)
		}
	}
	// Whitespace-only trims to the default (empty) suffix, which is valid.
	if got, err := NormalizeCookieSuffix("  "); err != nil || got != "" {
		t.Errorf(`NormalizeCookieSuffix("  ") = %q, %v`, got, err)
	}
	for _, bad := range []string{"a b", "a/b", strings.Repeat("x", 33), "！"} {
		if _, err := NormalizeCookieSuffix(bad); err == nil {
			t.Errorf("NormalizeCookieSuffix(%q) accepted", bad)
		}
	}
}

// server.log_retention_days: unset means 7 days, 0 means memory only, and
// out-of-range values fail startup.
func TestLogRetention(t *testing.T) {
	state := ServerState{}
	if got := state.LogRetention(); got != DefaultEventLogRetentionDays {
		t.Fatalf("default retention = %d", got)
	}
	zero := 0
	state.LogRetentionDays = &zero
	if got := state.LogRetention(); got != 0 {
		t.Fatalf("explicit 0 = %d", got)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "state.yaml")
	for _, bad := range []int{-1, 3651} {
		body := "server:\n  log_retention_days: " + strconv.Itoa(bad) + "\n"
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadState(path); err == nil {
			t.Errorf("log_retention_days %d accepted", bad)
		}
	}

	body := "server:\n  log_retention_days: 3\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	st, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Server.LogRetention() != 3 {
		t.Fatalf("retention = %d", st.Server.LogRetention())
	}
}
