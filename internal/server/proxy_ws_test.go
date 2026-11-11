package server

// WebSocket 升级必须透明穿过访问日志的状态码包装：ReverseProxy 需要拿到被
// hijack 的原始连接，任何包在 ResponseWriter 外面的装饰器都不能挡住它。

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/seqyuan/goprox/internal/config"
	"github.com/seqyuan/goprox/internal/eventlog"
)

func TestWebSocketUpgradeThroughGateway(t *testing.T) {
	// Raw upgrade backend: 101 + echo one byte through the tunnel.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		if !strings.Contains(string(buf[:n]), "Upgrade: websocket") {
			conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
			return
		}
		conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
		if _, err := conn.Read(buf); err != nil {
			return
		}
		conn.Write([]byte("Z"))
		// Returning closes the tunnel, so the gateway handler finishes and the
		// access record below is written deterministically.
	}()
	_, backendPort, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	cfgPath := config.UserConfigPath(dir, "alice")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0700); err != nil {
		t.Fatal(err)
	}
	cfg := "auth:\n  password_hash: \"" + strings.Repeat("1", 64) + "\"\nservices:\n" +
		"  - id: ws\n    name: WS\n    host: 127.0.0.1\n    port: " + backendPort +
		"\n    path: /ws\n    websocket: true\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	srv := New(&config.StateConfig{
		Server: config.ServerState{Host: "127.0.0.1", Port: 30152},
		Auth:   config.AuthState{SessionSecret: "testsecret", SessionTTL: 86400},
	}, dir)

	// A real listener is required: the upgrade hijacks the connection.
	gw := httptest.NewServer(srv.Handler())
	defer gw.Close()
	client, err := net.Dial("tcp", strings.TrimPrefix(gw.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))

	req, err := http.NewRequest("GET", gw.URL+"/proxy/alice/ws/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = strings.TrimPrefix(gw.URL, "http://")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Cookie", aliceSessionCookie())
	if err := req.Write(client); err != nil {
		t.Fatal(err)
	}

	br := bufio.NewReader(client)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101, got %d", resp.StatusCode)
	}
	if _, err := client.Write([]byte("A")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 1)
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("tunnel read failed: %v", err)
	}
	if string(got) != "Z" {
		t.Fatalf("tunnel echo = %q, want Z", got)
	}

	// The upgrade is still one access entry for the card: routing a WebSocket
	// through the status-capturing wrapper must not turn it into a fake failure
	// (nor into a missing record).
	deadline := time.Now().Add(5 * time.Second)
	for {
		events := srv.events.List("alice", 0)
		if len(events) > 0 {
			if len(events) != 1 || events[0].Kind != eventlog.KindAccess || !events[0].OK {
				t.Fatalf("events = %+v", events)
			}
			if events[0].Service != "WS" {
				t.Fatalf("recorded service = %q", events[0].Service)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no access event recorded for the WebSocket upgrade")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
