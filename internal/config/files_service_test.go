package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeUserYAML(t *testing.T, dir, username, body string) string {
	t.Helper()
	path := UserConfigPath(dir, username)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	cfg := "auth:\n  password_hash: \"" + strings.Repeat("1", 64) + "\"\n" + body
	if err := os.WriteFile(path, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadFilesService(t *testing.T) {
	root := t.TempDir()
	dir := t.TempDir()
	path := writeUserYAML(t, dir, "alice",
		"services:\n  - id: data\n    name: 数据盘\n    kind: files\n    path: /data\n    root: "+root+"/.\n")

	cfg, err := LoadUserConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Services) != 1 {
		t.Fatalf("services = %d, want 1", len(cfg.Services))
	}
	svc := cfg.Services[0]
	if svc.Kind != ServiceKindFiles {
		t.Errorf("kind = %q", svc.Kind)
	}
	if svc.Root != filepath.Clean(root) {
		t.Errorf("root = %q, want cleaned %q", svc.Root, root)
	}
	// A files service carries no backend settings.
	if svc.BackendPath != "" || svc.WebSocket || svc.AuthBootstrap != nil {
		t.Errorf("files service kept proxy settings: %+v", svc)
	}
}

func TestLoadFilesServiceSkippedWithoutUsableRoot(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"missing root":  "services:\n  - id: data\n    name: d\n    kind: files\n    path: /data\n",
		"relative root": "services:\n  - id: data\n    name: d\n    kind: files\n    path: /data\n    root: data\n",
		"not a dir":     "services:\n  - id: data\n    name: d\n    kind: files\n    path: /data\n    root: " + writeTempFile(t) + "\n",
		"nonexistent":   "services:\n  - id: data\n    name: d\n    kind: files\n    path: /data\n    root: /nope/definitely-not-here-7c1\n",
	} {
		path := writeUserYAML(t, dir, "alice", body)
		cfg, err := LoadUserConfig(path)
		if err != nil {
			t.Fatalf("%s: LoadUserConfig: %v", name, err)
		}
		if len(cfg.Services) != 0 {
			t.Errorf("%s: service should be skipped, got %+v", name, cfg.Services)
		}
	}
}

func writeTempFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(p, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadUnknownKindFallsBackToProxy(t *testing.T) {
	dir := t.TempDir()
	path := writeUserYAML(t, dir, "alice",
		"services:\n  - id: app\n    name: a\n    kind: websocket\n    host: 127.0.0.1\n    port: 8080\n    path: /app\n")
	cfg, err := LoadUserConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Services) != 1 || cfg.Services[0].Kind != ServiceKindProxy {
		t.Fatalf("unexpected services: %+v", cfg.Services)
	}
}

func TestLoadProxyServiceDropsStrayRoot(t *testing.T) {
	dir := t.TempDir()
	path := writeUserYAML(t, dir, "alice",
		"services:\n  - id: app\n    name: a\n    host: 127.0.0.1\n    port: 8080\n    path: /app\n    root: /data\n    show_hidden: true\n")
	cfg, err := LoadUserConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Services[0].Root != "" || cfg.Services[0].ShowHidden {
		t.Fatalf("proxy service kept files-only fields: %+v", cfg.Services[0])
	}
}

func TestAddFilesServicePersistsAndReloads(t *testing.T) {
	root := t.TempDir()
	dir := t.TempDir()
	path := writeUserYAML(t, dir, "alice", "services: []\n")

	if _, err := AddService(path, ServiceConfig{
		Name:       "数据盘",
		Kind:       ServiceKindFiles,
		Root:       root,
		Path:       "/data",
		ShowHidden: true,
	}); err != nil {
		t.Fatalf("AddService: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"kind: files", "root: " + root, "show_hidden: true"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("persisted YAML missing %q:\n%s", want, raw)
		}
	}

	cfg, err := LoadUserConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Services) != 1 || cfg.Services[0].Kind != ServiceKindFiles || cfg.Services[0].Root != root || !cfg.Services[0].ShowHidden {
		t.Fatalf("reloaded service = %+v", cfg.Services)
	}
}

func TestAddFilesServiceRejectsMissingRoot(t *testing.T) {
	dir := t.TempDir()
	path := writeUserYAML(t, dir, "alice", "services: []\n")
	if _, err := AddService(path, ServiceConfig{Name: "x", Kind: ServiceKindFiles, Path: "/x"}); err == nil {
		t.Fatal("expected an error for a files service without root")
	}
}

func TestNormalizeServiceKind(t *testing.T) {
	cases := map[string]struct {
		want string
		ok   bool
	}{
		"":        {ServiceKindProxy, true},
		"proxy":   {ServiceKindProxy, true},
		" FILES ": {ServiceKindFiles, true},
		"weird":   {"", false},
	}
	for in, want := range cases {
		got, ok := NormalizeServiceKind(in)
		if got != want.want || ok != want.ok {
			t.Errorf("NormalizeServiceKind(%q) = %q,%v want %q,%v", in, got, ok, want.want, want.ok)
		}
	}
}

// A files root must never overlap the gateway config directory: a logged-in
// user could otherwise download state.yaml (session secret) and every user's
// password hash / TOTP secret, then forge sessions for any account.
func TestFilesRootRejectsConfigDirOverlap(t *testing.T) {
	base := t.TempDir()
	configDir := filepath.Join(base, "config")
	usersDir := filepath.Join(configDir, "users")
	share := filepath.Join(base, "share")
	for _, dir := range []string{usersDir, share} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	configPath := filepath.Join(usersDir, "alice.yaml")

	for _, root := range []string{
		configDir,                   // the config dir itself
		usersDir,                    // the users dir
		base,                        // an ancestor containing the config dir
		filepath.Join(base, "link"), // symlink to the config dir (below)
	} {
		if root == filepath.Join(base, "link") {
			if err := os.Symlink(configDir, root); err != nil {
				t.Skipf("symlink: %v", err)
			}
		}
		if _, err := ValidateFileRoot(root, configPath, nil); err == nil {
			t.Errorf("ValidateFileRoot(%q) accepted a config-dir overlap", root)
		}
	}

	// A sibling directory is fine.
	if got, err := ValidateFileRoot(share, configPath, nil); err != nil || got != share {
		t.Fatalf("ValidateFileRoot(share) = %q, %v", got, err)
	}
}

// The loader must drop a hand-written config that tries the same thing.
func TestLoadFilesServiceSkipsConfigDirRoot(t *testing.T) {
	dir := t.TempDir()
	usersDir := filepath.Join(dir, "users")
	if err := os.MkdirAll(usersDir, 0700); err != nil {
		t.Fatal(err)
	}
	root := dir // contains the config dir
	path := writeUserYAML(t, dir, "alice",
		"services:\n  - id: data\n    name: d\n    kind: files\n    path: /data\n    root: "+root+"\n")
	cfg, err := LoadUserConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Services) != 0 {
		t.Fatalf("service must be skipped, got %+v", cfg.Services)
	}
}

// The API is the user-facing entry point: creating or editing a card that
// points at the config dir must fail with a clear error.
func TestAddFilesServiceRejectsConfigDirRoot(t *testing.T) {
	dir := t.TempDir()
	path := writeUserYAML(t, dir, "alice", "services: []\n")
	if _, err := AddService(path, ServiceConfig{Name: "cfg", Kind: ServiceKindFiles, Path: "/cfg", Root: dir}); err == nil {
		t.Fatal("AddService accepted a root overlapping the config dir")
	}
}

// server.files_roots (allowlist) must confine kind:"files" roots to the
// configured directories, including through symlinks; an empty list keeps the
// permissive single-admin behavior.
func TestFilesRootAllowlist(t *testing.T) {
	base := t.TempDir()
	configDir := filepath.Join(base, "config")
	usersDir := filepath.Join(configDir, "users")
	allowed := filepath.Join(base, "shared")
	other := filepath.Join(base, "private")
	for _, dir := range []string{usersDir, allowed, filepath.Join(allowed, "sub"), other} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	configPath := filepath.Join(usersDir, "alice.yaml")
	t.Cleanup(func() { SetFilesRootAllowlist(nil) })

	SetFilesRootAllowlist([]string{allowed})
	if _, err := ValidateFileRoot(filepath.Join(allowed, "sub"), configPath, nil); err != nil {
		t.Fatalf("allowed subtree rejected: %v", err)
	}
	if _, err := ValidateFileRoot(allowed, configPath, nil); err != nil {
		t.Fatalf("allowed root rejected: %v", err)
	}
	if _, err := ValidateFileRoot(other, configPath, nil); err == nil {
		t.Fatal("root outside the allowlist was accepted")
	}

	// A symlink inside the allowed tree that points outside must not pass.
	link := filepath.Join(allowed, "escape")
	if err := os.Symlink(other, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if _, err := ValidateFileRoot(link, configPath, nil); err == nil {
		t.Fatal("symlink escaping the allowlist was accepted")
	}

	// Empty allowlist: permissive again (the config-dir rule still applies).
	SetFilesRootAllowlist(nil)
	if _, err := ValidateFileRoot(other, configPath, nil); err != nil {
		t.Fatalf("empty allowlist should be permissive, got %v", err)
	}
}

func TestNormalizeFilesRoots(t *testing.T) {
	dir := t.TempDir()
	got, err := NormalizeFilesRoots([]string{dir + "/", dir})
	if err != nil {
		t.Fatalf("NormalizeFilesRoots: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("duplicates not collapsed: %v", got)
	}
	if _, err := NormalizeFilesRoots([]string{"relative"}); err == nil {
		t.Fatal("relative entry accepted")
	}
	if _, err := NormalizeFilesRoots([]string{filepath.Join(dir, "nope")}); err == nil {
		t.Fatal("missing directory accepted")
	}
	if got, err := NormalizeFilesRoots(nil); err != nil || got != nil {
		t.Fatalf("empty list = %v, %v", got, err)
	}
}

// A user-level files_roots list narrows that user's file cards further; an
// invalid list fails closed (all of the user's files cards are dropped).
func TestUserFilesRoots(t *testing.T) {
	base := t.TempDir()
	configDir := filepath.Join(base, "config")
	home := filepath.Join(base, "home-alice")
	other := filepath.Join(base, "home-bob")
	for _, dir := range []string{filepath.Join(configDir, "users"), home, filepath.Join(home, "data"), other} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	svc := "services:\n  - id: data\n    name: d\n    kind: files\n    path: /data\n    root: %s\n"

	// Inside the user's list: kept.
	path := writeUserYAML(t, configDir, "alice", "files_roots:\n  - "+home+"\n"+fmt.Sprintf(svc, filepath.Join(home, "data")))
	cfg, err := LoadUserConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Services) != 1 {
		t.Fatalf("allowed user root was dropped: %+v", cfg.Services)
	}

	// Outside the user's list: dropped.
	path = writeUserYAML(t, configDir, "alice", "files_roots:\n  - "+home+"\n"+fmt.Sprintf(svc, other))
	cfg, err = LoadUserConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Services) != 0 {
		t.Fatalf("user root outside files_roots was loaded: %+v", cfg.Services)
	}

	// A symlink inside the allowed tree pointing outside is resolved and
	// refused.
	link := filepath.Join(home, "escape")
	if err := os.Symlink(other, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	path = writeUserYAML(t, configDir, "alice", "files_roots:\n  - "+home+"\n"+fmt.Sprintf(svc, link))
	cfg, err = LoadUserConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Services) != 0 {
		t.Fatalf("symlink escaping user files_roots was loaded: %+v", cfg.Services)
	}

	// Invalid list (relative path): fail closed even for a valid root.
	path = writeUserYAML(t, configDir, "alice", "files_roots:\n  - relative\n"+fmt.Sprintf(svc, filepath.Join(home, "data")))
	cfg, err = LoadUserConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Services) != 0 {
		t.Fatalf("invalid files_roots must disable the user's files services: %+v", cfg.Services)
	}
}

// The API path (AddService/UpdateService) must enforce the user list too.
func TestAddFilesServiceRespectsUserRoots(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "home")
	outside := filepath.Join(base, "outside")
	for _, dir := range []string{home, outside} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	path := writeUserYAML(t, dir, "alice", "files_roots:\n  - "+home+"\nservices: []\n")

	if _, err := AddService(path, ServiceConfig{Name: "ok", Kind: ServiceKindFiles, Path: "/ok", Root: home}); err != nil {
		t.Fatalf("root inside user files_roots rejected: %v", err)
	}
	if _, err := AddService(path, ServiceConfig{Name: "bad", Kind: ServiceKindFiles, Path: "/bad", Root: outside}); err == nil {
		t.Fatal("root outside user files_roots accepted")
	}
}

// Service CRUD rewrites the services block only: an administrator-managed
// files_roots list must survive add/update/layout writes.
func TestUserFilesRootsSurviveServiceWrites(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "home")
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := writeUserYAML(t, dir, "alice", "files_roots:\n  - "+home+"\nservices: []\n")

	added, err := AddService(path, ServiceConfig{Name: "data", Kind: ServiceKindFiles, Path: "/data", Root: home})
	if err != nil {
		t.Fatalf("AddService: %v", err)
	}
	if err := UpdateService(path, added.ID, ServiceUpdate{Name: stringPtr("数据"), ShowHidden: boolPtr(true)}); err != nil {
		t.Fatalf("UpdateService: %v", err)
	}
	if err := UpdateServicesLayout(path, []LayoutItem{{ID: added.ID, Order: 0, Category: "共享"}}); err != nil {
		t.Fatalf("UpdateServicesLayout: %v", err)
	}

	cfg, err := LoadUserConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.FilesRoots) != 1 || cfg.FilesRoots[0] != home {
		t.Fatalf("files_roots lost by service writes: %+v", cfg.FilesRoots)
	}
	if len(cfg.Services) != 1 || !cfg.Services[0].ShowHidden {
		t.Fatalf("service update not applied: %+v", cfg.Services)
	}
}

func stringPtr(s string) *string { return &s }
func boolPtr(b bool) *bool       { return &b }
