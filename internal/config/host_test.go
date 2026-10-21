package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeHostname(t *testing.T) {
	valid := map[string]string{
		"Hugo.GW.Example.COM.": "hugo.gw.example.com",
		"hugo.localhost":       "hugo.localhost",
	}
	for in, want := range valid {
		got, err := NormalizeHostname(in)
		if err != nil || got != want {
			t.Errorf("NormalizeHostname(%q) = %q, %v; want %q", in, got, err, want)
		}
	}

	invalid := []string{
		"", "hugo", "127.0.0.1", "hugo.example.com:8080",
		"hugo/example.com", "*.example.com", "-bad.example.com",
		"bad-.example.com", "a..b",
	}
	for _, in := range invalid {
		if got, err := NormalizeHostname(in); err == nil {
			t.Errorf("NormalizeHostname(%q) = %q, want error", in, got)
		}
	}
}

func TestNormalizeHostnamesDedupesAndDropsInvalid(t *testing.T) {
	out, dropped := NormalizeHostnames([]string{
		"A.example.com", "a.example.com", "bad", "b.example.com",
	})
	if !reflect.DeepEqual(out, []string{"a.example.com", "b.example.com"}) {
		t.Fatalf("out = %#v", out)
	}
	if !reflect.DeepEqual(dropped, []string{"bad"}) {
		t.Fatalf("dropped = %#v", dropped)
	}
}

func TestHostFromHostPort(t *testing.T) {
	cases := map[string]string{
		"Hugo.GW.Example.COM.:30152": "hugo.gw.example.com",
		"hugo.example.com":           "hugo.example.com",
		"[::1]:30152":                "::1",
	}
	for in, want := range cases {
		if got := HostFromHostPort(in); got != want {
			t.Errorf("HostFromHostPort(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizePublicHost(t *testing.T) {
	valid := map[string]string{
		"GW.Example.COM":       "gw.example.com",
		"gw.example.com:30152": "gw.example.com:30152",
		"gw.example.com.":      "gw.example.com",
	}
	for in, want := range valid {
		got, err := NormalizePublicHost(in)
		if err != nil || got != want {
			t.Errorf("NormalizePublicHost(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"https://gw.example.com", "127.0.0.1", "gw.example.com:bad",
		"gw.example.com/path", "gw:30152:extra",
	} {
		if got, err := NormalizePublicHost(in); err == nil {
			t.Errorf("NormalizePublicHost(%q) = %q, want error", in, got)
		}
	}
}

func TestNormalizeCookieDomain(t *testing.T) {
	got, err := NormalizeCookieDomain(".GW.Example.COM.")
	if err != nil || got != ".gw.example.com" {
		t.Fatalf("NormalizeCookieDomain = %q, %v", got, err)
	}
	if got, err := NormalizeCookieDomain(".localhost"); err != nil || got != ".localhost" {
		t.Fatalf("NormalizeCookieDomain(.localhost) = %q, %v", got, err)
	}
	for _, in := range []string{
		"gw.example.com", ".com", ".127.0.0.1", ".a..b", ".gw.example.com:443",
	} {
		if got, err := NormalizeCookieDomain(in); err == nil {
			t.Errorf("NormalizeCookieDomain(%q) = %q, want error", in, got)
		}
	}
}

func TestLoadStateNormalizesVHostFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), StateFile)
	raw := "server:\n  host: 127.0.0.1\n  port: 30152\n  public_host: GW.Example.COM:30152\n  public_scheme: HTTPS\n  cookie_domain: .GW.Example.COM.\n  trusted_proxy: \"\"\nauth:\n  session_ttl: 60\n"
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	st, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Server.PublicHost != "gw.example.com:30152" {
		t.Fatalf("public_host = %q", st.Server.PublicHost)
	}
	if st.Server.PublicScheme != "https" {
		t.Fatalf("public_scheme = %q", st.Server.PublicScheme)
	}
	if st.Server.CookieDomain != ".gw.example.com" {
		t.Fatalf("cookie_domain = %q", st.Server.CookieDomain)
	}
}

func TestSerializeServicesPreservesHostnames(t *testing.T) {
	out := serializeServices([]ServiceConfig{{
		ID: "hugo", Name: "Hugo", Host: "127.0.0.1", Port: 1313, Path: "/hugo",
		Hostnames: []string{"hugo.gw.example.com"},
	}})
	got, ok := out[0]["hostnames"].([]string)
	if !ok || !reflect.DeepEqual(got, []string{"hugo.gw.example.com"}) {
		t.Fatalf("hostnames not serialized: %#v", out[0]["hostnames"])
	}
}

func TestUpdateServicePreservesHostnames(t *testing.T) {
	path := newTestConfig(t)
	if _, err := AddService(path, ServiceConfig{
		ID: "hugo", Name: "Hugo", Host: "127.0.0.1", Port: 1313, Path: "/hugo",
		Hostnames: []string{"hugo.gw.example.com"},
	}); err != nil {
		t.Fatal(err)
	}
	newName := "Hugo docs"
	if err := UpdateService(path, "hugo", ServiceUpdate{Name: &newName}); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadUserConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	svc := ServiceByID(cfg.Services, "hugo")
	if svc == nil || !reflect.DeepEqual(svc.Hostnames, []string{"hugo.gw.example.com"}) {
		t.Fatalf("hostnames dropped by UpdateService: %+v", svc)
	}
}

func TestLoadUserConfigNormalizesHostnames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user.yaml")
	raw := "auth:\n  password_hash: \"" + strings.Repeat("1", 64) + "\"\n" +
		"services:\n  - id: hugo\n    name: Hugo\n    host: 127.0.0.1\n    port: 1313\n    path: /hugo\n" +
		"    hostnames:\n      - Hugo.GW.Example.COM.\n      - hugo.gw.example.com\n      - bad\n"
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadUserConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Services) != 1 {
		t.Fatalf("services = %d", len(cfg.Services))
	}
	if !reflect.DeepEqual(cfg.Services[0].Hostnames, []string{"hugo.gw.example.com"}) {
		t.Fatalf("hostnames = %#v", cfg.Services[0].Hostnames)
	}
}

func TestHostWithinCookieDomain(t *testing.T) {
	cases := []struct {
		host, domain string
		want         bool
	}{
		{"hugo.example.test", ".example.test", true},
		{"example.test", ".example.test", true},
		{"hugo.other.test", ".example.test", false},
		{"notexample.test", ".example.test", false},
		{"hugo.example.test", "", true},
	}
	for _, c := range cases {
		if got := HostWithinCookieDomain(c.host, c.domain); got != c.want {
			t.Errorf("HostWithinCookieDomain(%q, %q) = %v, want %v", c.host, c.domain, got, c.want)
		}
	}
}
