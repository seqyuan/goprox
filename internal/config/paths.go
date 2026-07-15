package config

import (
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	DefaultHost         = "0.0.0.0"
	DefaultPort         = 1907
	DefaultSessionTTL   = 86400
	DefaultHomePrefix   = "/home"
	DefaultHomePrefixMac = "/Users"
	UserConfigDir       = ".config/goprox"
	UserConfigFile      = "config.yaml"
	StateDir            = "goprox"
	StateFile           = "state.yaml"
	PidFile             = "daemon.pid"
	LogFile             = "goprox.log"
)

var usernameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

func HomePrefix() string {
	if _, err := os.Stat("/Users"); err == nil {
		return DefaultHomePrefixMac
	}
	return DefaultHomePrefix
}

func DefaultStatePath() string {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, StateDir, StateFile)
}

func DefaultUserConfigPath(username ...string) string {
	home, _ := os.UserHomeDir()
	if len(username) > 0 && username[0] != "" {
		if u, err := getUserHome(username[0], HomePrefix()); err == nil {
			home = u
		}
	}
	return filepath.Join(home, UserConfigDir, UserConfigFile)
}

func GetUserConfigPath(username, homePrefix string) string {
	home, _ := getUserHome(username, homePrefix)
	return filepath.Join(home, UserConfigDir, UserConfigFile)
}

func GetPidPath(statePath string) string {
	return filepath.Join(filepath.Dir(statePath), PidFile)
}

func GetLogPath(statePath string) string {
	return filepath.Join(filepath.Dir(statePath), LogFile)
}

func getUserHome(username string, homePrefix string) (string, error) {
	currentUser := os.Getenv("USER")
	if username == currentUser {
		return os.UserHomeDir()
	}
	// Use the provided home prefix for other users
	return filepath.Join(homePrefix, username), nil
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
