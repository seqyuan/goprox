package main

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/seqyuan/goprox/internal/config"
)

// freePort reserves and releases a loopback port, returning a number that is
// very likely still free when the gateway binds it.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

func serveOpts(t *testing.T, configDir string, extra ...string) options {
	t.Helper()
	opts, err := parseOptions(append([]string{
		"-d", configDir,
		"--host", "127.0.0.1",
		"--port", itoa(freePort(t)),
	}, extra...))
	if err != nil {
		t.Fatal(err)
	}
	return opts
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// The startup path must bind, persist what it bound, and serve the login page.
func TestStartGatewayServesLoginAndPersistsListen(t *testing.T) {
	dir := t.TempDir()
	opts := serveOpts(t, dir)

	g, err := startGateway(opts)
	if err != nil {
		t.Fatalf("startGateway: %v", err)
	}
	t.Cleanup(func() { g.http.Close() })

	if g.tls {
		t.Fatal("plain HTTP start reported TLS")
	}
	if got := g.listener.Addr().(*net.TCPAddr).Port; got != opts.port {
		t.Fatalf("bound port %d, want %d", got, opts.port)
	}
	state, err := config.LoadState(config.StatePath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if state.Server.Port != opts.port || state.Server.Host != "127.0.0.1" {
		t.Fatalf("persisted listen = %s:%d", state.Server.Host, state.Server.Port)
	}

	go func() { _ = g.serve() }()
	body := getEventually(t, "http://"+g.listener.Addr().String()+"/", nil)
	if !strings.Contains(body, "login") {
		t.Fatalf("unexpected body: %.200s", body)
	}
}

// --tls-selfsigned must produce a working HTTPS listener (and persist both
// paths so a restart keeps serving TLS).
func TestStartGatewayTLS(t *testing.T) {
	dir := t.TempDir()
	opts := serveOpts(t, dir, "--tls-selfsigned")

	g, err := startGateway(opts)
	if err != nil {
		t.Fatalf("startGateway: %v", err)
	}
	t.Cleanup(func() { g.http.Close() })
	if !g.tls {
		t.Fatal("TLS not enabled")
	}
	if g.state.Server.TLSCert == "" || g.state.Server.TLSKey == "" {
		t.Fatalf("tls paths not set in state: %+v", g.state.Server)
	}
	if !filepath.IsAbs(g.state.Server.TLSCert) {
		t.Fatalf("cert path not absolute: %q", g.state.Server.TLSCert)
	}

	go func() { _ = g.serve() }()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	body := getEventually(t, "https://"+g.listener.Addr().String()+"/", client)
	if !strings.Contains(body, "login") {
		t.Fatalf("unexpected body: %.200s", body)
	}

	// A restart must reuse the persisted pair without --tls-selfsigned.
	opts2 := serveOpts(t, dir)
	g2, err := startGateway(opts2)
	if err != nil {
		t.Fatalf("restart with persisted TLS: %v", err)
	}
	t.Cleanup(func() { g2.http.Close() })
	if !g2.tls {
		t.Fatal("persisted TLS not picked up on restart")
	}
}

// vhost services without public_host/cookie_domain must fail startup with a
// clear error (and must not leak the listener).
func TestStartGatewayRejectsIncompleteVHostConfig(t *testing.T) {
	dir := t.TempDir()
	if _, err := config.LoadState(config.StatePath(dir)); err != nil {
		t.Fatal(err)
	}
	cfgPath := config.UserConfigPath(dir, "alice")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0700); err != nil {
		t.Fatal(err)
	}
	body := "auth:\n  password_hash: \"" + strings.Repeat("1", 64) + "\"\nservices:\n" +
		"  - id: hugo\n    name: hugo\n    host: 127.0.0.1\n    port: 1313\n    path: /hugo\n" +
		"    hostnames:\n      - hugo.example.test\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := startGateway(serveOpts(t, dir)); err == nil {
		t.Fatal("startGateway accepted vhost services without public_host/cookie_domain")
	} else if !strings.Contains(err.Error(), "public_host") {
		t.Fatalf("error should name the missing setting, got %v", err)
	}
}

// A port already in use must be reported as a startup error, not a panic, and
// must not overwrite the persisted listen config.
func TestStartGatewayPortInUse(t *testing.T) {
	dir := t.TempDir()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	opts, err := parseOptions([]string{"-d", dir, "--host", "127.0.0.1", "--port", itoa(port)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := startGateway(opts); err == nil {
		t.Fatal("startGateway succeeded on a port that is already bound")
	}
}

// Invalid CLI values must be rejected before binding anything.
func TestStartGatewayRejectsInvalidFlags(t *testing.T) {
	dir := t.TempDir()
	cases := [][]string{
		{"--trusted-proxy", "not-a-cidr"},
		{"--public-host", "bad host"},
		{"--public-scheme", "ftp"},
		{"--cookie-domain", "com"},
	}
	for _, extra := range cases {
		opts, err := parseOptions(append([]string{"-d", dir, "--host", "127.0.0.1", "--port", itoa(freePort(t))}, extra...))
		if err != nil {
			t.Fatalf("parseOptions(%v): %v", extra, err)
		}
		if _, err := startGateway(opts); err == nil {
			t.Errorf("startGateway accepted %v", extra)
		}
	}
}

func getEventually(t *testing.T, url string, client *http.Client) string {
	t.Helper()
	if client == nil {
		client = http.DefaultClient
	}
	client.Timeout = 2 * time.Second
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err != nil {
			lastErr = err
			time.Sleep(20 * time.Millisecond)
			continue
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = err
			time.Sleep(20 * time.Millisecond)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d", resp.StatusCode)
		}
		return string(b)
	}
	t.Fatalf("server did not answer %s: %v", url, lastErr)
	return ""
}
