package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

type UserConfig struct {
	Auth     UserAuthConfig  `yaml:"auth"`
	Services []ServiceConfig `yaml:"services"`
	// DefaultService names the service (by ID) that unclaimed bare gateway
	// paths route to when no route cookie / Referer points anywhere. Root-based
	// SPAs (Nuxt/Next client routers that cannot understand a /proxy/ prefix)
	// then work at the gateway root with zero app changes.
	DefaultService string `yaml:"default_service,omitempty"`
}

type UserAuthConfig struct {
	PasswordHash string `yaml:"password_hash"`
	TOTPSecret   string `yaml:"totp_secret,omitempty"` // base32 TOTP secret; presence enables 2FA
}

// UserRecord contains a loaded user and their config path.

type UserRecord struct {
	Username   string
	ConfigPath string
	Config     UserConfig
}

// HashPassword hashes a password with bcrypt (cost 10). Kept here for the
// CLI commands; the auth package is the canonical implementation.

func HashPassword(password string) string {
	pw := []byte(password)
	if len(pw) > 72 { // bcrypt input limit; truncate consistently with auth
		pw = pw[:72]
	}
	hash, err := bcrypt.GenerateFromPassword(pw, bcrypt.DefaultCost)
	if err != nil {
		// Unreachable for valid input; keep the account locked.
		h := sha256.Sum256(pw)
		return hex.EncodeToString(h[:])
	}
	return string(hash)
}

// IsValidPasswordHash accepts bcrypt hashes ("$2...", 60 chars) and legacy
// unsalted SHA-256 hex hashes (64 chars).

func IsValidPasswordHash(hash string) bool {
	hash = strings.TrimSpace(hash)
	if strings.HasPrefix(hash, "$2") && len(hash) == 60 {
		return true
	}
	if len(hash) == 64 {
		if _, err := hex.DecodeString(hash); err == nil {
			return true
		}
	}
	return false
}

// IsWritable checks if the config file can actually be written by this process.
// A permission-bit check is not enough: owner-write bits would report true even
// when the process is not the file owner. Probe with a write-open instead.

func IsWritable(path string) bool {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// NormalizePath ensures a path starts with / and has no trailing /.

func NormalizePath(p string) string {
	p = strings.TrimSpace(p)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = strings.TrimRight(p, "/")
	if p == "" {
		p = "/"
	}
	return p
}

// pathSegmentRe matches a single safe URL path segment. Service paths become
// part of proxy URLs, injected <base href> tags, and route-cookie values, so
// anything outside this set (quotes, <>, ;, spaces, ?#) would corrupt pages,
// cookies, or routing.

func ValidatePath(p string) error {
	if p == "" || p == "/" {
		return nil
	}
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("path must start with /")
	}
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == "" {
			return fmt.Errorf("path cannot contain empty segments (double slash)")
		}
		if seg == "." || seg == ".." {
			return fmt.Errorf("path cannot contain %q segments", seg)
		}
		if !pathSegmentRe.MatchString(seg) {
			return fmt.Errorf("path segment %q contains invalid characters (allowed: A-Z a-z 0-9 . _ ~ -)", seg)
		}
	}
	return nil
}

func normalizePath(p string) string {
	return NormalizePath(p)
}

// validateAuthBootstrap normalizes a service's auth_bootstrap block, returning
// (nil,false) when the block is nil or unusable (unknown mode, missing token
// source, or an unparseable TokenRegex).

func EnsureUserConfig(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	cfg := UserConfig{
		Auth: UserAuthConfig{
			PasswordHash: "0000000000000000000000000000000000000000000000000000000000000000",
		},
		Services: []ServiceConfig{},
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	// Create with 0600: the config dir is owned by the gateway operator.
	if err := writeFileAtomic(path, data, 0600); err != nil {
		return err
	}
	fmt.Printf("[goprox] created user config: %s\n", path)
	return nil
}

// CreateUserConfig atomically creates a user config with the given password
// hash. Unlike EnsureUserConfig (which writes an idempotent placeholder), it
// refuses to overwrite an existing account, so two concurrent `goprox user`
// processes cannot clobber each other's password.

func CreateUserConfig(path, passwordHash string) error {
	if !IsValidPasswordHash(passwordHash) {
		return fmt.Errorf("invalid password hash")
	}
	return withConfigLock(path, func() error {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("user config already exists: %s", path)
		}
		cfg := UserConfig{
			Auth:     UserAuthConfig{PasswordHash: passwordHash},
			Services: []ServiceConfig{},
		}
		data, err := yaml.Marshal(cfg)
		if err != nil {
			return err
		}
		return writeFileAtomic(path, data, 0600)
	})
}

// RemoveUserConfig deletes a user config while holding the same cross-process
// lock, so a concurrent `goprox passwd` cannot recreate/overwrite it mid-delete.

func RemoveUserConfig(path string) error {
	return withConfigLock(path, func() error {
		return os.Remove(path)
	})
}

// warnedInvalidPath remembers (configPath, serviceID) pairs whose service was
// skipped for an invalid path, so registry scans (every 10s) don't log the
// same warning repeatedly. The entries are tiny and rare.

func LoadUserConfig(path string) (*UserConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var cfg UserConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	// Validate password hash: bcrypt or legacy SHA-256 hex; otherwise the
	// account is locked until the operator runs `goprox passwd`.
	if !IsValidPasswordHash(cfg.Auth.PasswordHash) {
		cfg.Auth.PasswordHash = "0000000000000000000000000000000000000000000000000000000000000000"
	} else if !strings.HasPrefix(cfg.Auth.PasswordHash, "$2") {
		// Legacy SHA-256 hex is case-insensitive; bcrypt is not.
		cfg.Auth.PasswordHash = strings.ToLower(cfg.Auth.PasswordHash)
	}

	// Ensure services array is not nil
	if cfg.Services == nil {
		cfg.Services = []ServiceConfig{}
	}

	// Normalize service paths. Services with characters that would break
	// proxied pages (<base> injection), route cookies, or routing are skipped
	// and reported once so the operator can fix the config.
	for i := 0; i < len(cfg.Services); {
		rawPath := cfg.Services[i].Path
		if strings.TrimSpace(rawPath) == "" {
			// AddService auto-generates a path for new services, but a
			// hand-written config with no path would otherwise become a catch-all
			// "/" service and silently claim unrelated routes. Require an explicit
			// path (use "/" deliberately if a catch-all is intended).
			key := path + "\x00" + cfg.Services[i].ID + "\x00empty-path"
			if _, loaded := warnedInvalidPath.LoadOrStore(key, struct{}{}); !loaded {
				log.Printf("[goprox] skip service %q of %s: path is required (use \"/\" for a root service)", cfg.Services[i].ID, path)
			}
			cfg.Services = append(cfg.Services[:i], cfg.Services[i+1:]...)
			continue
		}
		cfg.Services[i].Path = normalizePath(rawPath)
		if err := ValidatePath(cfg.Services[i].Path); err != nil {
			key := path + "\x00" + cfg.Services[i].ID
			if _, loaded := warnedInvalidPath.LoadOrStore(key, struct{}{}); !loaded {
				log.Printf("[goprox] skip service %q of %s: invalid path %q: %v",
					cfg.Services[i].ID, path, cfg.Services[i].Path, err)
			}
			cfg.Services = append(cfg.Services[:i], cfg.Services[i+1:]...)
			continue
		}
		if cfg.Services[i].Host == "" {
			cfg.Services[i].Host = "127.0.0.1"
		}
		// A service is either a proxy to host:port or a built-in read-only file
		// browser over a local directory. Normalize the kind first: an unknown
		// kind must not silently turn into a proxy target with an empty host.
		kind, ok := NormalizeServiceKind(cfg.Services[i].Kind)
		if !ok {
			key := path + "\x00" + cfg.Services[i].ID + "\x00kind"
			if _, loaded := warnedInvalidPath.LoadOrStore(key, struct{}{}); !loaded {
				log.Printf("[goprox] service %q of %s: unknown kind %q ignored; treating it as %q",
					cfg.Services[i].ID, path, cfg.Services[i].Kind, ServiceKindProxy)
			}
			kind = ServiceKindProxy
		}
		cfg.Services[i].Kind = kind
		if kind == ServiceKindFiles {
			root, err := ValidateFileRoot(cfg.Services[i].Root, path)
			if err != nil {
				key := path + "\x00" + cfg.Services[i].ID + "\x00root"
				if _, loaded := warnedInvalidPath.LoadOrStore(key, struct{}{}); !loaded {
					log.Printf("[goprox] skip files service %q of %s: %v", cfg.Services[i].ID, path, err)
				}
				cfg.Services = append(cfg.Services[:i], cfg.Services[i+1:]...)
				continue
			}
			cfg.Services[i].Root = root
			// A files service has no backend: drop proxy-only settings so a
			// later kind switch cannot resurrect a stale host/port/bootstrap.
			cfg.Services[i].BackendPath = ""
			cfg.Services[i].WebSocket = false
			cfg.Services[i].AuthBootstrap = nil
		} else {
			cfg.Services[i].Root = ""
			cfg.Services[i].ShowHidden = false
			// A backend that runs on this machine is often addressed the way the
			// operator opens it in a browser (its LAN IP). Collapse that to loopback
			// when the backend also listens there, so hairpin routing/firewalls
			// cannot break the card and every component agrees on one spelling.
			if normalized := NormalizeBackendHost(cfg.Services[i].Host, cfg.Services[i].Port); normalized != cfg.Services[i].Host {
				key := path + "\x00" + cfg.Services[i].ID + "\x00backendhost"
				if _, loaded := warnedInvalidPath.LoadOrStore(key, struct{}{}); !loaded {
					log.Printf("[goprox] service %q of %s: backend host %q is this machine; using %s:%d",
						cfg.Services[i].ID, path, cfg.Services[i].Host, normalized, cfg.Services[i].Port)
				}
				cfg.Services[i].Host = normalized
			}
		}
		// Normalize/validate auth_bootstrap. A block that names no usable token
		// source is dropped (with a one-time warning) rather than half-applied:
		// with no token the gateway would just leave the backend's 401 in place,
		// which is the same as not configuring it at all.
		if b, ok := validateAuthBootstrap(cfg.Services[i].AuthBootstrap); ok {
			cfg.Services[i].AuthBootstrap = b
		} else if cfg.Services[i].AuthBootstrap != nil {
			key := path + "\x00" + cfg.Services[i].ID + "\x00bootstrap"
			if _, loaded := warnedInvalidPath.LoadOrStore(key, struct{}{}); !loaded {
				log.Printf("[goprox] service %q of %s: invalid auth_bootstrap ignored", cfg.Services[i].ID, path)
			}
			cfg.Services[i].AuthBootstrap = nil
		}
		// Virtual-host names are optional; invalid entries are dropped with a
		// one-time warning so the service remains usable through path routing.
		hostnames, droppedHosts := NormalizeHostnames(cfg.Services[i].Hostnames)
		if len(droppedHosts) > 0 {
			key := path + "\x00" + cfg.Services[i].ID + "\x00hostnames"
			if _, loaded := warnedInvalidPath.LoadOrStore(key, struct{}{}); !loaded {
				log.Printf("[goprox] service %q of %s: invalid hostnames ignored: %v",
					cfg.Services[i].ID, path, droppedHosts)
			}
		}
		cfg.Services[i].Hostnames = hostnames
		i++
	}

	// Validate the default-service reference: it must name an existing service
	// ID. A stale reference is dropped (with a one-time warning) so the operator
	// notices the typo without breaking the whole account.
	if cfg.DefaultService != "" && !serviceWithID(cfg.Services, cfg.DefaultService) {
		key := path + "\x00" + cfg.DefaultService
		if _, loaded := warnedInvalidPath.LoadOrStore(key, struct{}{}); !loaded {
			log.Printf("[goprox] default_service %q of %s does not match any service id; ignored",
				cfg.DefaultService, path)
		}
		cfg.DefaultService = ""
	}

	return &cfg, nil
}

// loadRawConfig loads the raw YAML map to preserve structure for writes.

func loadRawConfig(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	if raw == nil {
		raw = make(map[string]interface{})
	}
	return raw, nil
}

// saveRawConfig writes raw YAML to a file.

func saveRawConfig(path string, raw map[string]interface{}) error {
	data, err := yaml.Marshal(raw)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data, 0600)
}

// UpdatePasswordHash updates only the password hash in a user config.

func UpdatePasswordHash(path, hash string) error {
	return withConfigLock(path, func() error {
		raw, err := loadRawConfig(path)
		if err != nil {
			return err
		}
		auth, _ := raw["auth"].(map[string]interface{})
		if auth == nil {
			auth = make(map[string]interface{})
		}
		auth["password_hash"] = hash
		raw["auth"] = auth
		return saveRawConfig(path, raw)
	})
}

// UpdateTOTPSecret updates only the TOTP secret in a user config. An empty
// secret removes the field (disabling 2FA).

func UpdateTOTPSecret(path, secret string) error {
	return withConfigLock(path, func() error {
		raw, err := loadRawConfig(path)
		if err != nil {
			return err
		}
		auth, _ := raw["auth"].(map[string]interface{})
		if auth == nil {
			auth = make(map[string]interface{})
		}
		if secret == "" {
			delete(auth, "totp_secret")
		} else {
			auth["totp_secret"] = secret
		}
		raw["auth"] = auth
		return saveRawConfig(path, raw)
	})
}

// Config lock for safe concurrent writes

func withConfigLock(path string, fn func() error) error {
	mu, _ := configLocks.LoadOrStore(path, &sync.Mutex{})
	m := mu.(*sync.Mutex)
	m.Lock()
	defer m.Unlock()

	// The lock file lives next to the config. Create the directory first: on a
	// fresh install `goprox user alice` runs before the gateway has created
	// config/users, so O_EXCL would otherwise fail with ENOENT.
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	// Cross-process serialization: the CLI (goprox passwd/2fa-reset/sso) and a
	// running gateway may write the same file concurrently. The lock file sits
	// next to the config, is ignored by the users-dir scanner (*.yaml only),
	// and is removed on release.
	unlock, err := lockConfigFile(path + ".lock")
	if err != nil {
		return fmt.Errorf("lock config %s: %w", path, err)
	}
	defer unlock()
	return fn()
}

// AddService adds a new service to a user config and returns the service as
// persisted (with a guaranteed-unique ID and path).

var pathSegmentRe = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)

var warnedInvalidPath sync.Map

var configLocks sync.Map
