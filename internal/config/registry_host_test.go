package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
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
	want := []string{"alice/a", "alice/b"}
	if !reflect.DeepEqual(conflicts["dup.example.test"], want) {
		t.Fatalf("conflicts = %#v, want %#v", conflicts["dup.example.test"], want)
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

func TestRegistryHostOwners(t *testing.T) {
	dir := t.TempDir()
	writeHostUser(t, dir, "alice", "shared.example.test")
	writeHostUser(t, dir, "bob", "shared.example.test")
	r := NewUserRegistry(dir)
	r.Reload()

	owners := r.HostOwners("shared.example.test", "alice", "svc")
	if !reflect.DeepEqual(owners, []string{"bob/svc"}) {
		t.Fatalf("owners = %#v", owners)
	}
	all := r.HostOwners("shared.example.test", "", "")
	if !reflect.DeepEqual(all, []string{"alice/svc", "bob/svc"}) {
		t.Fatalf("all owners = %#v", all)
	}
}

// A service whose path is "/" owns every path under /proxy/<user>/, while a
// more specific path still wins. Previously the root service only matched the
// exact prefix and its favicon/subresources 404ed.
func TestFindServiceRootPathMatchesSubpaths(t *testing.T) {
	dir := t.TempDir()
	cfgPath := UserConfigPath(dir, "alice")
	cfg := "auth:\n  password_hash: \"" + strings.Repeat("1", 64) + "\"\nservices:\n" +
		"  - id: root\n    name: Root\n    host: 127.0.0.1\n    port: 1\n    path: /\n" +
		"  - id: app\n    name: App\n    host: 127.0.0.1\n    port: 2\n    path: /app\n"
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	r := NewUserRegistry(dir)
	r.Reload()

	if m := r.FindService("/proxy/alice/favicon.ico"); m == nil || m.Service.ID != "root" || m.RemainingPath != "/favicon.ico" {
		t.Fatalf("root service match = %+v", m)
	}
	if m := r.FindService("/proxy/alice/app/x"); m == nil || m.Service.ID != "app" || m.RemainingPath != "/x" {
		t.Fatalf("specific service must win: %+v", m)
	}
	if m := r.FindService("/proxy/alice/"); m == nil || m.Service.ID != "root" || m.RemainingPath != "/" {
		t.Fatalf("root service root match = %+v", m)
	}
}
