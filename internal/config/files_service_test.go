package config

import (
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
