package config

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// probeDialTimeout bounds the loopback reachability probe. It runs at most
// once per backend address per process (and once per negativeTTL afterwards),
// so a slow probe can never show up on the request path.
const probeDialTimeout = 300 * time.Millisecond

// loopbackProbeNegativeTTL is how long a failed loopback probe is remembered.
// A backend that is simply not started yet must not pin the LAN spelling for
// the whole process lifetime: after this TTL the probe is retried.
const loopbackProbeNegativeTTL = 2 * time.Minute

type probeResult struct {
	ok bool
	at time.Time
}

var loopbackProbes sync.Map // "loopback:port" -> probeResult

// NormalizeBackendHost rewrites a backend host that names this machine through
// one of its own addresses to the loopback address, keeping the port.
//
// Operators (and customers) commonly fill in the address they open in a browser
// — http://192.168.0.106:3000 — even when the backend runs on the gateway's own
// machine. Dialing the LAN address from the same host relies on hairpin routing
// (blocked by some firewalls, missing in many container networks), and the two
// spellings then disagree between config, logs and upstream redirects. Reducing
// them to one canonical spelling keeps everything consistent, and is a no-op for
// genuinely remote backends.
//
// The rewrite is deliberately conservative:
//   - "localhost", wildcard binds (0.0.0.0/::) and addresses bound to a local
//     interface are candidates;
//   - DNS names are never rewritten (they may resolve elsewhere);
//   - a candidate is only rewritten when the backend also accepts loopback
//     connections, so a server bound exclusively to its LAN interface keeps
//     working exactly as before.
func NormalizeBackendHost(host string, port int) string {
	raw := strings.TrimSpace(host)
	if raw == "" || port <= 0 {
		return host
	}

	// Bracketed IPv6 literals are accepted in config; normalize for parsing.
	bare := strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]")
	lower := strings.ToLower(bare)
	ip := net.ParseIP(lower)

	isLocal := false
	switch {
	case ip == nil && lower == "localhost":
		isLocal = true
	case ip == nil:
		return host // DNS name: leave the operator's choice alone
	case ip.IsLoopback():
		return host // already canonical
	case ip.IsUnspecified():
		isLocal = true // a bind address; not dialable on every platform
	case isLocalInterfaceIP(ip):
		isLocal = true
	}
	if !isLocal {
		return host
	}

	loopback := "127.0.0.1"
	if ip != nil && ip.To4() == nil {
		loopback = "::1" // IPv6-only spelling: keep the family
	}
	if !backendAcceptsLoopback(loopback, port) {
		return host
	}
	return loopback
}

// backendAcceptsLoopback reports whether the backend answers on the loopback
// address. Positive answers are cached for the process; negative ones expire
// after loopbackProbeNegativeTTL so a backend started later is picked up.
func backendAcceptsLoopback(loopback string, port int) bool {
	key := net.JoinHostPort(loopback, strconv.Itoa(port))
	if v, ok := loopbackProbes.Load(key); ok {
		res := v.(probeResult)
		if res.ok || time.Since(res.at) < loopbackProbeNegativeTTL {
			return res.ok
		}
	}

	conn, err := net.DialTimeout("tcp", key, probeDialTimeout)
	ok := err == nil
	if ok {
		conn.Close()
	}
	loopbackProbes.Store(key, probeResult{ok: ok, at: time.Now()})
	return ok
}

// ResetBackendHostProbes clears the loopback probe cache. Only tests use it.
func ResetBackendHostProbes() {
	loopbackProbes.Range(func(key, _ any) bool {
		loopbackProbes.Delete(key)
		return true
	})
}
