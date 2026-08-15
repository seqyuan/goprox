package config

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	DefaultHost       = "0.0.0.0"
	DefaultPort       = 1908
	DefaultSessionTTL = 86400
	StateFile         = "state.yaml"
	PidFile           = "daemon.pid"
	LogFile           = "goprox.log"
	UsersDirName      = "users"
)

var usernameRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$`)

// DefaultConfigDir returns <program directory>/config. The config folder sits
// next to the binary so the whole directory can be copied around as a unit.
// Note: os.Executable resolves symlinks on Linux, so "copy, don't symlink".
func DefaultConfigDir() string {
	exe, err := os.Executable()
	if err != nil {
		// Fall back to the working directory when the executable path is unknown.
		wd, _ := os.Getwd()
		return filepath.Join(wd, "config")
	}
	return filepath.Join(filepath.Dir(exe), "config")
}

func StatePath(configDir string) string {
	return filepath.Join(configDir, StateFile)
}

func PidPath(configDir string) string {
	return filepath.Join(configDir, PidFile)
}

func LogPath(configDir string) string {
	return filepath.Join(configDir, LogFile)
}

func UsersDir(configDir string) string {
	return filepath.Join(configDir, UsersDirName)
}

func UserConfigPath(configDir, username string) string {
	return filepath.Join(UsersDir(configDir), username+".yaml")
}

func IsValidUsername(name string) bool {
	return usernameRe.MatchString(name)
}

func SlugifyName(name string) string {
	slug := strings.ToLower(strings.TrimSpace(name))
	slug = strings.ReplaceAll(slug, " ", "-")
	re := regexp.MustCompile(`[^a-z0-9_-]`)
	slug = re.ReplaceAllString(slug, "")
	re = regexp.MustCompile(`-+`)
	slug = re.ReplaceAllString(slug, "-")
	slug = strings.Trim(slug, "-")
	if slug == "" {
		return "service"
	}
	return slug
}

func ServicePathFromName(name string) string {
	return "/" + SlugifyName(name)
}

var localHosts = map[string]bool{
	"127.0.0.1": true,
	"localhost": true,
	"::1":       true,
}

// privateIP reports whether an IP is a loopback or private (RFC 1918 / IPv6
// ULA) address. Link-local addresses (169.254.0.0/16 and fe80::/10) are
// deliberately rejected: cloud metadata services (AWS/GCP/Azure IMDS) live in
// that range, and proxying to them would let a gateway user read instance
// credentials.
func privateIP(ip net.IP) bool {
	// Normalize IPv4-mapped addresses (::ffff:a.b.c.d) so the checks below
	// apply to the real IPv4 address.
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}

	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate()
}

// ResolveAllowedIPs resolves a backend host and returns concrete addresses
// only when every resolved address is loopback/private. Literal IPs are
// validated directly; localhost and *.localhost map to loopback. Unresolvable
// hostnames and any non-private address are rejected (deny-by-default).
func ResolveAllowedIPs(ctx context.Context, host string) ([]net.IP, error) {
	lower := strings.ToLower(strings.TrimSpace(host))

	if ip := net.ParseIP(lower); ip != nil {
		if !privateIP(ip) {
			return nil, &HostError{Host: lower}
		}
		return []net.IP{ip}, nil
	}

	// localhost / *.localhost are loopback by definition; pin both loopbacks
	// so backends bound to either address family stay reachable.
	if localHosts[lower] || strings.HasSuffix(lower, ".localhost") {
		return []net.IP{net.IPv4(127, 0, 0, 1), net.ParseIP("::1")}, nil
	}

	lookupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(lookupCtx, lower)
	if err != nil || len(addrs) == 0 {
		return nil, &HostError{Host: lower}
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		if !privateIP(a.IP) {
			return nil, &HostError{Host: lower}
		}
		ips = append(ips, a.IP)
	}
	return ips, nil
}

// IsPrivateOrLocal accepts loopback/private IPs and hostnames that resolve
// entirely to private addresses. It is the write-time allowlist check for
// backend hosts; SafeDialContext re-checks at connection time.
func IsPrivateOrLocal(host string) bool {
	_, err := ResolveAllowedIPs(context.Background(), host)
	return err == nil
}

// SafeDialContext re-validates the backend address at connection time and
// dials the exact IPs it validated. This closes the DNS-rebinding gap between
// the write-time allowlist check and the actual request: a hostname that later
// resolves to a public or link-local address is rejected here instead of
// dialed. The validated IP is dialed directly so no second lookup can rebind.
func SafeDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	ips, err := ResolveAllowedIPs(ctx, host)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var lastErr error
	for _, ip := range ips {
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = &HostError{Host: host}
	}
	return nil, lastErr
}

func AssertAllowedHost(host string) error {
	if !IsPrivateOrLocal(host) {
		return &HostError{Host: host}
	}
	return nil
}

// IsTrustedProxyTooBroad reports whether a trusted-proxy CIDR covers the whole
// address space (e.g. 0.0.0.0/0 or ::/0). Such a range would let any direct
// client spoof X-Forwarded-* headers, defeating login rate limiting and
// HTTPS/Secure-cookie detection.
func IsTrustedProxyTooBroad(cidr string) bool {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return false
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	ones, bits := ipnet.Mask.Size()
	return bits != 0 && ones == 0
}

type HostError struct {
	Host string
}

func (e *HostError) Error() string {
	return "backend host must be local or private network (127.0.0.1, 10.x, 172.16-31.x, 192.168.x), got: " + e.Host
}
