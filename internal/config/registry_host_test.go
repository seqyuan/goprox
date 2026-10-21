package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeHostUser(t *testing.T, configDir, username string, hostnames ...string) {
	t.Helper()
	path := UserConfigPath(configDir, username)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("auth:\n  password_hash: \"" + strings.Repeat("1", 64) + "\"\n")
	b.WriteString("services:\n")
	b.WriteString("  - id: svc\n    name: Svc\n    host: 127.0.0.1\n    port: 8080\n    path: /svc\n")
	if len(hostnames) > 0 {
		b.WriteString("    hostnames:\n")
		for _, h := range hostnames {
			b.WriteString("      - " + h + "\n")
		}
	}
	if err := os.WriteFile(path, []byte(b.String()), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestRegistryFindByHost(t *testing.T) {
	dir := t.TempDir()
	writeHostUser(t, dir, "alice", "Hugo.Example.Test.")
	r := NewUserRegistry(dir)
	r.Reload()

	target := r.FindByHost("hugo.example.test")
	if target == nil {
		t.Fatal("host not found")
	}
	if target.Username != "alice" || target.Service.ID != "svc" {
		t.Fatalf("target = %+v", target)
	}
	if !r.HasHosts() {
		t.Fatal("HasHosts = false")
	}
	if err := r.ValidateHosts(); err != nil {
		t.Fatalf("ValidateHosts: %v", err)
	}
}

func TestRegistryDuplicateHostDisabled(t *testing.T) {
	dir := t.TempDir()
	writeHostUser(t, dir, "alice", "shared.example.test", "alice.example.test")
	writeHostUser(t, dir, "bob", "shared.example.test")
	r := NewUserRegistry(dir)
	r.Reload()

	if target := r.FindByHost("shared.example.test"); target != nil {
		t.Fatalf("duplicate host must be disabled, got %+v", target)
	}
	if target := r.FindByHost("alice.example.test"); target == nil || target.Username != "alice" {
		t.Fatalf("unique host lost: %+v", target)
	}
	if err := r.ValidateHosts(); err == nil {
		t.Fatal("ValidateHosts must report the duplicate")
	}
	if !r.HasHosts() {
		t.Fatal("unique host should keep HasHosts true")
	}
}

func TestRegistryReloadUpdatesHosts(t *testing.T) {
	dir := t.TempDir()
	writeHostUser(t, dir, "alice", "old.example.test")
	r := NewUserRegistry(dir)
	r.Reload()
	if r.FindByHost("old.example.test") == nil {
		t.Fatal("old host missing")
	}

	writeHostUser(t, dir, "alice", "new.example.test")
	r.Reload()
	if r.FindByHost("old.example.test") != nil {
		t.Fatal("old host still routable after reload")
	}
	if target := r.FindByHost("new.example.test"); target == nil || target.Username != "alice" {
		t.Fatalf("new host not loaded: %+v", target)
	}
}

func TestBuildHostIndexSameUserDuplicate(t *testing.T) {
	users := map[string]*UserRecord{
		"alice": {
			Username: "alice",
			Config: UserConfig{Services: []ServiceConfig{
				{ID: "a", Hostnames: []string{"dup.example.test"}},
				{ID: "b", Hostnames: []string{"dup.example.test"}},
			}},
		},
	}
	hosts, conflicts := buildHostIndex(users)
	if _, ok := hosts["dup.example.test"]; ok {
		t.Fatal("duplicate within one user must not be routable")
	}
	if len(conflicts["dup.example.test"]) != 1 || conflicts["dup.example.test"][0] != "alice" {
		t.Fatalf("conflicts = %#v", conflicts)
	}
}

func TestRegistryHostLookupKeepsUserConfigSeparate(t *testing.T) {
	dir := t.TempDir()
	writeHostUser(t, dir, "alice", "a.example.test")
	r := NewUserRegistry(dir)
	r.Reload()
	target := r.FindByHost("a.example.test")
	if target == nil {
		t.Fatal("host not found")
	}
	if got := fmt.Sprintf("%s/%s", target.Username, target.Service.Path); got != "alice//svc" {
		t.Fatalf("unexpected target: %s", got)
	}
}
