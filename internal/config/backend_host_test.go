package config

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// listeningPort returns a port that is accepting connections on loopback.
func listeningPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func firstNonLoopbackIPv4(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("InterfaceAddrs: %v", err)
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() {
			continue
		}
		if v4 := ipNet.IP.To4(); v4 != nil {
			return v4.String()
		}
	}
	t.Skip("no non-loopback IPv4 address on this host")
	return ""
}

func TestNormalizeBackendHostCollapsesLocalSpellings(t *testing.T) {
	port := listeningPort(t)
	cases := []string{"localhost", "127.0.0.1", "0.0.0.0", firstNonLoopbackIPv4(t)}
	for _, host := range cases {
		got := NormalizeBackendHost(host, port)
		if got != "127.0.0.1" {
			t.Errorf("NormalizeBackendHost(%q, %d) = %q, want 127.0.0.1", host, port, got)
		}
	}
}

func TestNormalizeBackendHostKeepsLocalIPWhenLoopbackClosed(t *testing.T) {
	// No listener on this port: the backend may be bound to the LAN interface
	// only, so the operator's spelling must be preserved.
	lan := firstNonLoopbackIPv4(t)
	port := closedPort(t)
	if got := NormalizeBackendHost(lan, port); got != lan {
		t.Fatalf("NormalizeBackendHost(%q, %d) = %q, want unchanged", lan, port, got)
	}
}

func TestNormalizeBackendHostLeavesRemoteAndDNSHosts(t *testing.T) {
	port := listeningPort(t)
	for _, host := range []string{"192.0.2.10", "10.9.8.7.example.com", "sso.example.com"} {
		if got := NormalizeBackendHost(host, port); got != host {
			t.Errorf("NormalizeBackendHost(%q) = %q, want unchanged", host, got)
		}
	}
}

func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// The loader must apply the normalization, so every other component (dialing,
// self-loop checks, redirect rewriting) sees a single spelling.
func TestLoadUserConfigNormalizesLocalBackendHost(t *testing.T) {
	lan := firstNonLoopbackIPv4(t)
	port := listeningPort(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "alice.yaml")
	cfg := "auth:\n  password_hash: \"" + strings.Repeat("1", 64) + "\"\n" +
		"services:\n" +
		"  - id: app\n    host: " + lan + "\n    port: " + strconv.Itoa(port) + "\n    path: /app\n"
	if err := os.WriteFile(path, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadUserConfig(path)
	if err != nil {
		t.Fatalf("LoadUserConfig: %v", err)
	}
	if got := loaded.Services[0].Host; got != "127.0.0.1" {
		t.Fatalf("host = %q, want 127.0.0.1", got)
	}
}
