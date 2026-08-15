package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := EnsureUserConfig(path); err != nil {
		t.Fatal(err)
	}
	return path
}

// Two Chinese service names must not collide on the "service" slug: the second
// one gets a unique ID and a unique auto-generated path.
func TestAddServiceChineseNamesGetUniqueIDs(t *testing.T) {
	path := newTestConfig(t)

	a, err := AddService(path, ServiceConfig{ID: SlugifyName("数据分析平台"), Name: "数据分析平台", Host: "127.0.0.1", Port: 8888})
	if err != nil {
		t.Fatal(err)
	}
	b, err := AddService(path, ServiceConfig{ID: SlugifyName("单细胞分析"), Name: "单细胞分析", Host: "127.0.0.1", Port: 8889})
	if err != nil {
		t.Fatal(err)
	}

	if a.ID == b.ID {
		t.Fatalf("IDs collided: %q == %q", a.ID, b.ID)
	}
	if a.Path == b.Path {
		t.Fatalf("paths collided: %q == %q", a.Path, b.Path)
	}
	if a.Path == "" || !strings.HasPrefix(a.Path, "/") {
		t.Fatalf("auto-generated path missing: %q", a.Path)
	}

	cfg, err := LoadUserConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(cfg.Services))
	}
}

// Ports outside 1-65535 must be rejected at the config layer.
func TestAddServiceRejectsInvalidPort(t *testing.T) {
	path := newTestConfig(t)
	if _, err := AddService(path, ServiceConfig{ID: "bad", Name: "Bad", Host: "127.0.0.1", Port: 70000}); err == nil {
		t.Fatal("expected port 70000 to be rejected")
	}
	if _, err := AddService(path, ServiceConfig{ID: "zero", Name: "Zero", Host: "127.0.0.1", Port: 0}); err == nil {
		t.Fatal("expected port 0 to be rejected")
	}
}

// Custom paths must be unique.
func TestAddServiceRejectsDuplicateCustomPath(t *testing.T) {
	path := newTestConfig(t)
	if _, err := AddService(path, ServiceConfig{ID: "a", Name: "A", Host: "127.0.0.1", Port: 1, Path: "/shared"}); err != nil {
		t.Fatal(err)
	}
	if _, err := AddService(path, ServiceConfig{ID: "b", Name: "B", Host: "127.0.0.1", Port: 2, Path: "/shared"}); err == nil {
		t.Fatal("expected duplicate custom path to be rejected")
	}
}

// UpdateService must reject invalid ports instead of silently ignoring them.
func TestUpdateServiceRejectsInvalidPort(t *testing.T) {
	path := newTestConfig(t)
	added, err := AddService(path, ServiceConfig{ID: "a", Name: "A", Host: "127.0.0.1", Port: 1})
	if err != nil {
		t.Fatal(err)
	}
	badPort := 70000
	upd := ServiceUpdate{Port: &badPort}
	if err := UpdateService(path, added.ID, upd); err == nil {
		t.Fatal("expected invalid port update to be rejected")
	}
}

// UpdateService must reject a path that collides with another service.
func TestUpdateServiceRejectsDuplicatePath(t *testing.T) {
	path := newTestConfig(t)
	a, err := AddService(path, ServiceConfig{ID: "a", Name: "A", Host: "127.0.0.1", Port: 1, Path: "/a"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := AddService(path, ServiceConfig{ID: "b", Name: "B", Host: "127.0.0.1", Port: 2, Path: "/b"})
	if err != nil {
		t.Fatal(err)
	}
	collide := "/a"
	upd := ServiceUpdate{Path: &collide}
	if err := UpdateService(path, b.ID, upd); err == nil {
		t.Fatalf("expected path collision update to be rejected (a=%q b=%q)", a.ID, b.ID)
	}
}

// AddService must return the persisted service (with final ID/path), and
// keep the caller-provided WebSocket flag as-is (defaulting is an API concern).
func TestAddServiceReturnsPersistedService(t *testing.T) {
	path := newTestConfig(t)
	added, err := AddService(path, ServiceConfig{ID: "s", Name: "S", Host: "127.0.0.1", Port: 8080, WebSocket: false})
	if err != nil {
		t.Fatal(err)
	}
	if added.ID != "s" || added.Path != "/s" || added.WebSocket {
		t.Fatalf("unexpected persisted service: %+v", added)
	}
	// A second service auto-generates a unique ID/path.
	second, err := AddService(path, ServiceConfig{ID: "s", Name: "S2", Host: "127.0.0.1", Port: 8081})
	if err != nil {
		t.Fatal(err)
	}
	if second.ID == "s" || second.Path == "/s" {
		t.Fatalf("second service not uniquified: %+v", second)
	}
}

// IsWritable must reflect reality, not just permission bits. When the file is
// read-only for the effective user the probe must return false.
func TestIsWritableUsesRealWriteProbe(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permission checks")
	}
	base := t.TempDir()
	path := filepath.Join(base, "c.yaml")
	if err := os.WriteFile(path, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	// Read-only for everyone -> not writable.
	if err := os.Chmod(path, 0444); err != nil {
		t.Fatal(err)
	}
	if IsWritable(path) {
		t.Fatal("0444 must not be writable")
	}

	// World-writable -> writable.
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if !IsWritable(path) {
		t.Fatal("0666 must be writable")
	}

	// Owner-write only, current process is the owner -> writable.
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	if !IsWritable(path) {
		t.Fatal("0640 owned by self must be writable")
	}
}

// A transient users-dir scan failure must keep the previous registry snapshot
// instead of dropping all users.
func TestReloadKeepsSnapshotOnScanError(t *testing.T) {
	configDir := t.TempDir()
	cfgPath := UserConfigPath(configDir, "alice")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0700); err != nil {
		t.Fatal(err)
	}
	valid := "auth:\n  password_hash: \"" + strings.Repeat("1", 64) + "\"\nservices: []\n"
	if err := os.WriteFile(cfgPath, []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}
	r := NewUserRegistry(configDir)
	r.Reload()
	if r.GetUser("alice") == nil {
		t.Fatal("valid user not loaded")
	}

	// Point the scan at a missing directory: Reload must keep the old snapshot.
	r.configDir = filepath.Join(configDir, "does-not-exist")
	r.Reload()
	if r.GetUser("alice") == nil {
		t.Fatal("registry dropped users after a transient scan error")
	}
}

// ValidatePath must reject characters that would corrupt proxy URLs, injected
// <base href> tags, or route-cookie values, and accept safe paths.
func TestValidatePath(t *testing.T) {
	valid := []string{
		"", "/", "/jupyter", "/my-app", "/sc_analysis/run-2", "/a.b_c~d",
	}
	for _, p := range valid {
		if err := ValidatePath(p); err != nil {
			t.Errorf("ValidatePath(%q) unexpected error: %v", p, err)
		}
	}

	invalid := []string{
		`/x"><script>alert(1)</script>`, // HTML/attribute injection
		"/foo bar",                      // spaces break cookie values and URLs
		`/foo"bar`,                      // quote breaks Set-Cookie and <base href>
		"/foo;bar",                      // semicolon breaks Set-Cookie
		"/foo?bar",                      // query markers corrupt routing
		"/foo#bar",
		"/foo/../bar", // traversal segments
		"/foo//bar",   // empty segment
		"/x\\y",
		"/x\x01y", // control char
	}
	for _, p := range invalid {
		if err := ValidatePath(p); err == nil {
			t.Errorf("ValidatePath(%q) expected error, got nil", p)
		}
	}
}

// LoadUserConfig must drop services with invalid paths instead of letting
// them break <base> injection / cookies for the whole user.
func TestLoadUserConfigSkipsInvalidPathService(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "user.yaml")
	yaml := "auth:\n  password_hash: \"" + strings.Repeat("2", 64) + "\"\n" +
		"services:\n" +
		"  - id: ok\n    name: ok\n    host: 127.0.0.1\n    port: 1\n    path: /fine\n" +
		"  - id: bad\n    name: bad\n    host: 127.0.0.1\n    port: 2\n    path: '/x\"><script>'\n"
	if err := os.WriteFile(cfgPath, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadUserConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Services) != 1 || cfg.Services[0].ID != "ok" {
		t.Fatalf("expected only the valid service to survive, got %+v", cfg.Services)
	}
}

// AddService must reject invalid custom paths instead of persisting them.
func TestAddServiceRejectsInvalidPath(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "user.yaml")
	if err := os.WriteFile(cfgPath, []byte("auth:\n  password_hash: \""+strings.Repeat("3", 64)+"\"\nservices: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	svc := ServiceConfig{Name: "x", Host: "127.0.0.1", Port: 8080, Path: `/bad"><base`}
	if _, err := AddService(cfgPath, svc); err == nil {
		t.Fatal("AddService accepted an invalid path")
	}
	svc.Path = "/good"
	if _, err := AddService(cfgPath, svc); err != nil {
		t.Fatalf("AddService rejected a valid path: %v", err)
	}
}
