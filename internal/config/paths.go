package config

import (
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

func IsPrivateOrLocal(host string) bool {
	lower := strings.ToLower(host)
	if localHosts[lower] {
		return true
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
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
	return ip.IsLoopback()
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
