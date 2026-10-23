package config

import (
	"os"
	"path/filepath"
	"reflect"
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

// Category grouping must be deterministic when services share an Order value
// (hand-written configs often omit order, leaving every service at 0). Groups
// follow first appearance in the input, matching the client renderer.
func TestGroupServicesByCategoryDeterministicOnTiedOrders(t *testing.T) {
	services := []ServiceConfig{
		{ID: "a", Name: "A", Category: "乙", Order: 0},
		{ID: "b", Name: "B", Category: "甲", Order: 0},
		{ID: "c", Name: "C", Category: "丙", Order: 0},
		{ID: "d", Name: "D", Category: "丁", Order: 0},
	}
	want := []string{"乙", "甲", "丙", "丁"}
	for i := 0; i < 25; i++ {
		groups := GroupServicesByCategory(services)
		got := make([]string, len(groups))
		for j, g := range groups {
			got[j] = g.Category
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("nondeterministic grouping: got %v want %v", got, want)
		}
	}
}

// Category order follows the lowest Order; within a category services keep
// Order order; an empty category maps to 未分类.
func TestGroupServicesByCategoryOrder(t *testing.T) {
	services := []ServiceConfig{
		{ID: "a1", Name: "A1", Category: "A", Order: 5},
		{ID: "b1", Name: "B1", Category: "B", Order: 1},
		{ID: "a0", Name: "A0", Category: "A", Order: 0},
		{ID: "u1", Name: "U1", Order: 3},
	}
	groups := GroupServicesByCategory(services)
	gotCats := []string{groups[0].Category, groups[1].Category, groups[2].Category}
	if !reflect.DeepEqual(gotCats, []string{"A", "B", "未分类"}) {
		t.Fatalf("category order = %v", gotCats)
	}
	if groups[0].Services[0].ID != "a0" || groups[0].Services[1].ID != "a1" {
		t.Fatalf("within-category order = %+v", groups[0].Services)
	}
}

// An auto-generated path must step aside when another service already owns
// "/"+ID as a custom path. Previously only the ID was uniquified, so this
// produced two services sharing one path.
func TestAddServiceAutoPathAvoidsCustomPathCollision(t *testing.T) {
	path := newTestConfig(t)
	if _, err := AddService(path, ServiceConfig{ID: "x", Name: "X", Host: "127.0.0.1", Port: 1, Path: "/myapp"}); err != nil {
		t.Fatal(err)
	}
	added, err := AddService(path, ServiceConfig{ID: SlugifyName("Myapp"), Name: "Myapp", Host: "127.0.0.1", Port: 2})
	if err != nil {
		t.Fatal(err)
	}
	if added.Path == "/myapp" {
		t.Fatalf("auto path collided with existing custom path: %q", added.Path)
	}

	cfg, err := LoadUserConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, s := range cfg.Services {
		if seen[s.Path] {
			t.Fatalf("duplicate service path persisted: %q", s.Path)
		}
		seen[s.Path] = true
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

// A failed scan (including a missing users dir on a fresh install) must still
// advance lastScan. Otherwise EnsureFresh retries the scan on every request,
// flooding the log and the filesystem.
func TestReloadScanErrorUpdatesLastScan(t *testing.T) {
	r := NewUserRegistry(filepath.Join(t.TempDir(), "missing"))
	r.Reload()
	if r.lastScan.IsZero() {
		t.Fatal("lastScan not updated after a failed scan")
	}
	before := r.lastScan
	// EnsureFresh must not rescan within the scan interval.
	r.EnsureFresh()
	if !r.lastScan.Equal(before) {
		t.Fatalf("EnsureFresh rescanned immediately after a failed scan: %v -> %v", before, r.lastScan)
	}
}

// Removing the service named by default_service must also clear the persisted
// top-level key. LoadUserConfig only drops a stale reference in memory, which
// would otherwise leave a dead ID in YAML and silently reactivate it if the
// same service ID were added again.
func TestRemoveServiceClearsDefaultService(t *testing.T) {
	path := newTestConfig(t)
	a, err := AddService(path, ServiceConfig{ID: "a", Name: "A", Host: "127.0.0.1", Port: 1})
	if err != nil {
		t.Fatal(err)
	}
	b, err := AddService(path, ServiceConfig{ID: "b", Name: "B", Host: "127.0.0.1", Port: 2})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := loadRawConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	raw["default_service"] = a.ID
	if err := saveRawConfig(path, raw); err != nil {
		t.Fatal(err)
	}

	// Removing a different service must keep a valid default reference.
	if err := RemoveService(path, b.ID); err != nil {
		t.Fatal(err)
	}
	raw, err = loadRawConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := raw["default_service"].(string); got != a.ID {
		t.Fatalf("default_service = %q, want %q", got, a.ID)
	}

	// Removing the referenced service must clear the key.
	if err := RemoveService(path, a.ID); err != nil {
		t.Fatal(err)
	}
	raw, err = loadRawConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["default_service"]; ok {
		t.Fatalf("stale default_service survived removal: %#v", raw["default_service"])
	}
}

// Config writes must be atomic (temp file + rename) so concurrent registry
// scans never observe a truncated YAML document.
func TestWriteFileAtomicReplacesCleanly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.yaml")
	if err := os.WriteFile(path, []byte("old: true\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(path, []byte("new: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new: true\n" {
		t.Fatalf("content = %q", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %o, want 0600", info.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("temporary file left behind: %s", e.Name())
		}
	}
}

// withConfigLock also takes a cross-process file lock; exercise the platform
// implementation so a build tag/API mistake fails the test suite.
func TestWithConfigLockTakesFileLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alice.yaml")
	if err := withConfigLock(path, func() error { return nil }); err != nil {
		t.Fatalf("withConfigLock: %v", err)
	}
	if _, err := os.Stat(path + ".lock"); err != nil {
		t.Fatalf("lock file missing: %v", err)
	}
}

// The auto-generated path comes from the service ID. Direct callers (outside
// the API, which slugifies names) must not be able to persist an invalid path
// that the next registry load would silently drop.
func TestAddServiceRejectsInvalidAutoPath(t *testing.T) {
	path := newTestConfig(t)
	if _, err := AddService(path, ServiceConfig{ID: "bad id", Name: "Bad", Host: "127.0.0.1", Port: 1}); err == nil {
		t.Fatal("AddService accepted an invalid auto-generated path")
	}
}
