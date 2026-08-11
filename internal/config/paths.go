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

// privateIP reports whether an IP is loopback, link-local, or in a private
// (RFC 1918 / IPv6 ULA) range.
func privateIP(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
			ip.IsPrivate() // covers IPv6 fd00::/8 ULA and fc00::/7
	}
	if ip4[0] == 10 {
		return true
	}
	if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
		return true
	}
	if ip4[0] == 192 && ip4[1] == 168 {
		return true
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

// IsPrivateOrLocal accepts loopback/private IPs and hostnames that resolve
// entirely to private addresses (deny-by-default: unresolvable or partially
// public hostnames are rejected).
func IsPrivateOrLocal(host string) bool {
	lower := strings.ToLower(strings.TrimSpace(host))
	if localHosts[lower] || strings.HasSuffix(lower, ".localhost") {
		return true
	}

	if ip := net.ParseIP(lower); ip != nil {
		return privateIP(ip)
	}

	// Hostname: require every resolved address to be private/local so a name
	// can't smuggle a public endpoint past the allowlist.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, lower)
	if err != nil || len(addrs) == 0 {
		return false
	}
	for _, a := range addrs {
		if !privateIP(a.IP) {
			return false
		}
	}
	return true
}

func AssertAllowedHost(host string) error {
	if !IsPrivateOrLocal(host) {
		return &HostError{Host: host}
	}
	return nil
}

type HostError struct {
	Host string
}

func (e *HostError) Error() string {
	return "backend host must be local or private network (127.0.0.1, 10.x, 172.16-31.x, 192.168.x), got: " + e.Host
}
