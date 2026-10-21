package config

import (
	"os"
	"path/filepath"
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
