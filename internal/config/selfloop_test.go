package config

import (
	"context"
	"net"
	"strconv"
	"testing"
)

// Loopback is always a local interface address, so it anchors every test
// below regardless of the machine's other interfaces.
func TestLocalInterfaceIPsIncludeLoopback(t *testing.T) {
	if !isLocalInterfaceIP(net.IPv4(127, 0, 0, 1)) {
		t.Fatal("127.0.0.1 must be reported as a local interface address")
	}
	if isLocalInterfaceIP(net.ParseIP("8.8.8.8")) {
		t.Fatal("public IP must not be reported as local")
	}
}

func TestAssertNotSelfTargetDisabledByDefault(t *testing.T) {
	// gatewayListenPort defaults to 0: no check, nothing rejected.
	if err := AssertNotSelfTarget("127.0.0.1", DefaultPort); err != nil {
		t.Fatalf("unexpected error with check disabled: %v", err)
	}
}

func TestAssertNotSelfTarget(t *testing.T) {
	const port = 30152
	SetGatewayListenPort(port)
	defer SetGatewayListenPort(0)

	// localhost/loopback on the gateway's own port is a self-loop.
	if err := AssertNotSelfTarget("localhost", port); err == nil {
		t.Fatal("localhost:30152 must be rejected as a self-loop")
	}
	if err := AssertNotSelfTarget("127.0.0.1", port); err == nil {
		t.Fatal("127.0.0.1:30152 must be rejected as a self-loop")
	}

	// Same machine, different port: the normal use case, must stay allowed.
	if err := AssertNotSelfTarget("localhost", port+1); err != nil {
		t.Fatalf("localhost:%d must be allowed, got %v", port+1, err)
	}
	// Public hosts are not local interfaces; the self-loop check must not fire
	// (they are rejected separately by AssertAllowedHost).
	if err := AssertNotSelfTarget("8.8.8.8", port); err != nil {
		t.Fatalf("public host must not trigger the self-loop check, got %v", err)
	}
}

// The dial-time backstop must refuse a connection that would bounce straight
// back into the gateway, before any socket is dialed.
func TestSafeDialContextRejectsSelfLoop(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	// A second listener on a different port stands in for an unrelated local
	// service that must remain dialable.
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()
	go func() {
		for {
			c, err := ln2.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	SetGatewayListenPort(port)
	defer SetGatewayListenPort(0)

	_, err = SafeDialContext(context.Background(), "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err == nil {
		t.Fatal("expected dial to the gateway's own listen address to be rejected")
	}

	// A different port on the same machine must still dial successfully.
	_, err = SafeDialContext(context.Background(), "tcp", ln2.Addr().String())
	if err != nil {
		t.Fatalf("expected dial to a non-gateway local listener to succeed, got %v", err)
	}
}

func TestAddServiceRejectsSelfLoop(t *testing.T) {
	const port = 30152
	SetGatewayListenPort(port)
	defer SetGatewayListenPort(0)

	path := newTestConfig(t)
	if _, err := AddService(path, ServiceConfig{ID: "loop", Name: "Loop", Host: "127.0.0.1", Port: port}); err == nil {
		t.Fatal("AddService accepted a backend that points back at the gateway")
	}
}

func TestUpdateServiceRejectsSelfLoop(t *testing.T) {
	const port = 30152
	SetGatewayListenPort(port)
	defer SetGatewayListenPort(0)

	path := newTestConfig(t)
	added, err := AddService(path, ServiceConfig{ID: "s", Name: "S", Host: "127.0.0.1", Port: 8080})
	if err != nil {
		t.Fatal(err)
	}
	bad := port
	if err := UpdateService(path, added.ID, ServiceUpdate{Port: &bad}); err == nil {
		t.Fatal("UpdateService accepted a port change that would self-loop")
	}
}
