package config

import (
	"context"
	"fmt"
	"net"
	"time"
)

// gatewayListenPort is the port the gateway itself listens on. It is set by
// the server before any proxy traffic flows. 0 (the default) disables the
// self-loop check, so standalone tools and tests that build configs directly
// keep working.
var gatewayListenPort int

// SetGatewayListenPort records the gateway's own listen port so that backend
// hosts pointing back at it can be rejected as self-loops.
func SetGatewayListenPort(port int) {
	gatewayListenPort = port
}

// localInterfaceIPs returns every IP address bound to a local interface
// (including loopback), normalized to 4-byte form for IPv4-mapped addresses.
func localInterfaceIPs() []net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			ip = ip4
		}
		ips = append(ips, ip)
	}
	return ips
}

// isLocalInterfaceIP reports whether ip is bound to a local interface.
func isLocalInterfaceIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	for _, lip := range localInterfaceIPs() {
		if lip.Equal(ip) {
			return true
		}
	}
	return false
}

// containsLocalInterfaceIP reports whether any resolved backend IP is bound to
// a local interface of this machine.
func containsLocalInterfaceIP(ips []net.IP) bool {
	for _, ip := range ips {
		if isLocalInterfaceIP(ip) {
			return true
		}
	}
	return false
}

// AssertNotSelfTarget rejects a backend host:port that resolves to this
// machine on the gateway's own listen port. Proxying such a target would loop
// the request straight back into the gateway forever. The check only fires
// when the port matches the gateway's listen port; a service on another port
// of the same machine (e.g. localhost:8080 Jupyter) is the normal use case
// and stays allowed.
func AssertNotSelfTarget(host string, port int) error {
	if gatewayListenPort == 0 || port != gatewayListenPort {
		return nil
	}
	if resolvesToSelf(host) {
		return fmt.Errorf("backend %s:%d points back at the gateway itself (self-loop rejected)", host, port)
	}
	return nil
}

// resolvesToSelf reports whether host resolves to a local interface address.
// It reuses ResolveAllowedIPs, so only private/loopback hosts can ever be
// considered; anything else returns false here and is rejected elsewhere.
func resolvesToSelf(host string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ips, err := ResolveAllowedIPs(ctx, host)
	if err != nil {
		return false
	}
	return containsLocalInterfaceIP(ips)
}
