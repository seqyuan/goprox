package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

// Service kinds. A service is either a proxy to a backend host:port or a
// built-in read-only file browser over a local directory.
const (
	ServiceKindProxy = "proxy"
	ServiceKindFiles = "files"
)

// NormalizeServiceKind validates a service kind. An empty value means the
// default (proxy); ok is false for an unrecognized kind.
func NormalizeServiceKind(kind string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "", ServiceKindProxy:
		return ServiceKindProxy, true
	case ServiceKindFiles:
		return ServiceKindFiles, true
	}
	return "", false
}

// ValidateFileRoot normalizes and checks the directory of a files service: it
// must be an absolute path to an existing, readable directory that does not
// overlap the gateway's own config directory.
//
// The overlap check is a privilege boundary, not tidiness. A files service is
// configured by any logged-in user, and the gateway serves whatever its own
// account can read; without this rule a normal user could mount
// <config dir>/ as a card and download state.yaml (session_secret) and
// users/*.yaml (password hashes, TOTP secrets), then forge a session for any
// account. The check runs on the symlink-resolved paths, so a link cannot be
// used to reach the config directory either.
func ValidateFileRoot(root, configPath string) (string, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return "", fmt.Errorf("目录路径不能为空（填写服务端绝对路径，例如 /data/share）")
	}
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("目录必须是绝对路径，例如 /data/share")
	}
	clean := filepath.Clean(root)
	st, err := os.Stat(clean)
	if err != nil {
		return "", fmt.Errorf("目录不可用：%v", err)
	}
	if !st.IsDir() {
		return "", fmt.Errorf("%s 不是目录", clean)
	}
	if err := assertNotConfigDir(clean, configPath); err != nil {
		return "", err
	}
	f, err := os.Open(clean)
	if err != nil {
		return "", fmt.Errorf("目录无法读取：%v", err)
	}
	// Probe an actual directory read: permission bits alone do not prove the
	// gateway account can list it.
	if _, err := f.ReadDir(1); err != nil && err != io.EOF {
		f.Close()
		return "", fmt.Errorf("目录无法读取：%v", err)
	}
	f.Close()
	return clean, nil
}

// assertNotConfigDir rejects a files root that is, contains, or sits inside the
// gateway config directory (<configDir>/users/<user>.yaml → <configDir>).
func assertNotConfigDir(root, configPath string) error {
	if strings.TrimSpace(configPath) == "" {
		return nil
	}
	configDir := filepath.Dir(filepath.Dir(configPath)) // <configDir>/users/
	if configDir == "" || configDir == "." {
		return nil
	}
	rootPath, cfgDir := resolveSymlinks(root), resolveSymlinks(configDir)
	if within(rootPath, cfgDir) || within(cfgDir, rootPath) {
		return fmt.Errorf("目录 %s 与网关配置目录重叠，禁止挂载：请指定要共享的具体子目录（如 /data/share），不要使用包含网关配置的上级目录", root)
	}
	return nil
}

// resolveSymlinks returns the canonical path, falling back to the input when it
// cannot be resolved (a missing path is reported by the caller's own checks).
func resolveSymlinks(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	return path
}

// within reports whether child is parent or lives under it.
func within(child, parent string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}

// ServiceConfig represents a single backend service.
type ServiceConfig struct {
	ID          string `yaml:"id" json:"id"`
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	Host        string `yaml:"host" json:"host"`
	Port        int    `yaml:"port" json:"port"`
	Path        string `yaml:"path" json:"path"`                                     // Frontend path (e.g., /jupyter)
	BackendPath string `yaml:"backend_path,omitempty" json:"backend_path,omitempty"` // Backend path prefix (e.g., /app/index.html)
	WebSocket   bool   `yaml:"websocket" json:"websocket"`
	// RootAbsolute routes bare (non-/proxy/) requests back to this service when
	// the Referer or route cookie points at it. Opt-in for apps that emit
	// root-absolute URLs (/docs/, /static/...); default_service remains the
	// fallback for requests without this context.
	RootAbsolute bool `yaml:"root_absolute,omitempty" json:"root_absolute,omitempty"`
	// Kind selects what the card serves: "" / "proxy" (default) proxies to
	// Host:Port, "files" serves the local directory Root as a read-only,
	// browsable tree (the gateway is the backend).
	Kind string `yaml:"kind,omitempty" json:"kind,omitempty"`
	// Root is the directory exposed by Kind == "files".
	Root string `yaml:"root,omitempty" json:"root,omitempty"`
	// ShowHidden lists dotfiles in a files service (default: hidden).
	ShowHidden bool `yaml:"show_hidden,omitempty" json:"show_hidden,omitempty"`
	// Hostnames gives this service one or more dedicated virtual hosts (for
	// example hugo.gw.example.com). A request whose Host matches is proxied to
	// this service at the root path, bypassing /proxy and default_service.
	Hostnames []string `yaml:"hostnames,omitempty" json:"hostnames,omitempty"`
	Category  string   `yaml:"category,omitempty" json:"category,omitempty"`
	Order     int      `yaml:"order,omitempty" json:"order,omitempty"`
	BWLimit   int64    `yaml:"bwlimit,omitempty" json:"bwlimit,omitempty"` // Per-service bandwidth cap in bytes/sec; 0 = unlimited
	// AuthBootstrap, when set, lets the gateway complete the backend's own
	// browser session handshake (see AuthBootstrapConfig).
	AuthBootstrap *AuthBootstrapConfig `yaml:"auth_bootstrap,omitempty" json:"auth_bootstrap,omitempty"`
}

// Bootstrap modes for AuthBootstrapConfig.Mode.
const (
	BootstrapModeStatic = "static" // literal TokenValue
	BootstrapModeFile   = "file"   // read TokenFile (optionally via TokenRegex)
	BootstrapModeLog    = "log"    // tail TokenLog, extract TokenRegex (last match)
)

// AuthBootstrapConfig lets the gateway finish a backend's own browser session
// handshake. Some local-first apps (e.g. DeepSeek Harness / dsh) mint a
// per-process startup token and answer an unauthenticated page request with
// 401 "authentication required" instead of a redirect, so a LAN browser can
// never reach the ?token= URL the app printed on loopback. When configured,
// the gateway converts that one response into a browser-visible 302 to the same
// path with ?<Param>=<token>, and the backend then issues its session cookie
// exactly as if the user had opened that URL directly.
//
// The exchange is generic (Jupyter, code-server, … use the same ?token=
// pattern); only where the token comes from is per-backend, which is what Mode
// selects.
type AuthBootstrapConfig struct {
	Mode       string `yaml:"mode" json:"mode"`                       // static | file | log
	Param      string `yaml:"param,omitempty" json:"param,omitempty"` // query param name, default "token"
	TokenValue string `yaml:"token_value,omitempty" json:"token_value,omitempty"`
	TokenFile  string `yaml:"token_file,omitempty" json:"token_file,omitempty"`
	TokenLog   string `yaml:"token_log,omitempty" json:"token_log,omitempty"`
	TokenRegex string `yaml:"token_regex,omitempty" json:"token_regex,omitempty"`
}

// UserConfig represents a user's configuration file.
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
var pathSegmentRe = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)

// ValidatePath checks a normalized path for characters safe to use in URLs,
// <base href> injection, and cookie values. Empty string is valid (means
// "auto-generate"). "/" is valid (root). Returns an error otherwise.
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
func validateAuthBootstrap(b *AuthBootstrapConfig) (*AuthBootstrapConfig, bool) {
	if b == nil {
		return nil, false
	}
	b.Mode = strings.ToLower(strings.TrimSpace(b.Mode))
	b.Param = strings.TrimSpace(b.Param)
	switch b.Mode {
	case BootstrapModeStatic:
		if strings.TrimSpace(b.TokenValue) == "" {
			return nil, false
		}
	case BootstrapModeFile:
		if strings.TrimSpace(b.TokenFile) == "" {
			return nil, false
		}
	case BootstrapModeLog:
		if strings.TrimSpace(b.TokenLog) == "" {
			return nil, false
		}
	default:
		return nil, false
	}
	if r := strings.TrimSpace(b.TokenRegex); r != "" {
		if _, err := regexp.Compile(r); err != nil {
			return nil, false
		}
		b.TokenRegex = r
	}
	return b, true
}

// EnsureUserConfig creates a default user config if it doesn't exist.
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
var warnedInvalidPath sync.Map

// LoadUserConfig loads a user config from a path.
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
var configLocks sync.Map

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
func AddService(configPath string, svc ServiceConfig) (ServiceConfig, error) {
	var added ServiceConfig
	err := withConfigLock(configPath, func() error {
		cfg, err := LoadUserConfig(configPath)
		if err != nil {
			return err
		}

		if svc.Host == "" {
			svc.Host = "127.0.0.1"
		}
		kind, ok := NormalizeServiceKind(svc.Kind)
		if !ok {
			return fmt.Errorf("未知的服务类型 %q（可选 proxy / files）", svc.Kind)
		}
		svc.Kind = kind
		if kind == ServiceKindFiles {
			root, err := ValidateFileRoot(svc.Root, configPath)
			if err != nil {
				return err
			}
			svc.Root = root
			svc.Port = 0 // a files service has no backend; port stays unused
			svc.BackendPath = ""
			svc.WebSocket = false
			svc.AuthBootstrap = nil
		} else {
			if err := AssertAllowedHost(svc.Host); err != nil {
				return err
			}
			if svc.Port < 1 || svc.Port > 65535 {
				return fmt.Errorf("port must be between 1 and 65535, got %d", svc.Port)
			}
			if svc.BWLimit < 0 {
				return fmt.Errorf("bwlimit must be >= 0 (bytes/sec), got %d", svc.BWLimit)
			}
			if err := AssertNotSelfTarget(svc.Host, svc.Port); err != nil {
				return err
			}
			svc.Root = ""
			svc.ShowHidden = false
		}

		// Guarantee a unique ID. Non-ASCII names all slugify to the same base
		// (e.g. "service"), so append a numeric suffix when needed.
		baseID := strings.TrimSpace(svc.ID)
		if baseID == "" {
			baseID = "service"
		}
		svc.ID = baseID
		for n := 2; serviceWithID(cfg.Services, svc.ID); n++ {
			svc.ID = fmt.Sprintf("%s-%d", baseID, n)
		}

		// Auto-generate a default path from the unique ID (slugified, always
		// safe); a custom path must be valid and not collide with an existing
		// one. The auto path is also collision-checked: a different service may
		// own "/"+ID as a custom path even though the ID itself is free.
		if svc.Path == "" {
			basePath := normalizePath("/" + svc.ID)
			svc.Path = basePath
			for n := 2; serviceWithPath(cfg.Services, svc.Path); n++ {
				svc.Path = fmt.Sprintf("%s-%d", basePath, n)
			}
			if err := ValidatePath(svc.Path); err != nil {
				return fmt.Errorf("invalid auto-generated service path from id %q: %w", svc.ID, err)
			}
		} else {
			svc.Path = normalizePath(svc.Path)
			if err := ValidatePath(svc.Path); err != nil {
				return fmt.Errorf("invalid service path: %w", err)
			}
			if serviceWithPath(cfg.Services, svc.Path) {
				return fmt.Errorf("service path %s already in use", svc.Path)
			}
		}

		// Find next order
		maxOrder := -1
		for _, s := range cfg.Services {
			if s.Order > maxOrder {
				maxOrder = s.Order
			}
		}
		svc.Order = maxOrder + 1

		hostnames, err := ValidateHostnamesForUser(cfg.Services, "", svc.Hostnames)
		if err != nil {
			return err
		}
		svc.Hostnames = hostnames

		cfg.Services = append(cfg.Services, svc)

		raw, _ := loadRawConfig(configPath)
		raw["services"] = serializeServices(cfg.Services)
		if err := saveRawConfig(configPath, raw); err != nil {
			return err
		}
		added = svc
		return nil
	})
	return added, err
}

func serviceWithID(services []ServiceConfig, id string) bool {
	for _, s := range services {
		if s.ID == id {
			return true
		}
	}
	return false
}

// ServiceByID returns a pointer to the service with the given ID, or nil.
func ServiceByID(services []ServiceConfig, id string) *ServiceConfig {
	for i := range services {
		if services[i].ID == id {
			return &services[i]
		}
	}
	return nil
}

func serviceWithPath(services []ServiceConfig, path string) bool {
	for _, s := range services {
		if s.Path == path {
			return true
		}
	}
	return false
}

// RemoveService removes a service from a user config.
func RemoveService(configPath, id string) error {
	return withConfigLock(configPath, func() error {
		cfg, err := LoadUserConfig(configPath)
		if err != nil {
			return err
		}

		found := false
		newServices := make([]ServiceConfig, 0, len(cfg.Services))
		for _, s := range cfg.Services {
			if s.ID != id {
				newServices = append(newServices, s)
			} else {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("service not found: %s", id)
		}
		cfg.Services = newServices

		raw, _ := loadRawConfig(configPath)
		raw["services"] = serializeServices(cfg.Services)
		// Drop a persisted default_service that pointed at the removed service.
		// LoadUserConfig only drops it in memory, so without this the stale ID
		// stays in YAML (and silently reactivates if the same ID is re-added).
		if def, _ := raw["default_service"].(string); def != "" && !serviceWithID(cfg.Services, def) {
			delete(raw, "default_service")
		}
		return saveRawConfig(configPath, raw)
	})
}

// ServiceUpdate holds optional fields for updating a service.
type ServiceUpdate struct {
	Name         *string   `json:"name,omitempty"`
	Description  *string   `json:"description,omitempty"`
	Host         *string   `json:"host,omitempty"`
	Port         *int      `json:"port,omitempty"`
	Path         *string   `json:"path,omitempty"`
	BackendPath  *string   `json:"backend_path,omitempty"`
	WebSocket    *bool     `json:"websocket,omitempty"`
	Category     *string   `json:"category,omitempty"`
	BWLimit      *int64    `json:"bwlimit,omitempty"`
	RootAbsolute *bool     `json:"root_absolute,omitempty"`
	Hostnames    *[]string `json:"hostnames,omitempty"`
	Kind         *string   `json:"kind,omitempty"`
	Root         *string   `json:"root,omitempty"`
	ShowHidden   *bool     `json:"show_hidden,omitempty"`
}

// ValidateHostnamesForUser normalizes hostnames and rejects invalid entries or
// collisions with another service in the same user config. selfID is the
// service being updated; pass "" when adding a new service.
func ValidateHostnamesForUser(services []ServiceConfig, selfID string, hostnames []string) ([]string, error) {
	normalized, dropped := NormalizeHostnames(hostnames)
	if len(dropped) > 0 {
		return nil, fmt.Errorf("invalid hostnames: %v", dropped)
	}
	for _, other := range services {
		if other.ID == selfID {
			continue
		}
		for _, existing := range other.Hostnames {
			for _, host := range normalized {
				if existing == host {
					return nil, fmt.Errorf("hostname %q is already used by service %q", host, other.ID)
				}
			}
		}
	}
	return normalized, nil
}

// UpdateService updates an existing service with optional fields.
func UpdateService(configPath, id string, update ServiceUpdate) error {
	return withConfigLock(configPath, func() error {
		cfg, err := LoadUserConfig(configPath)
		if err != nil {
			return err
		}

		found := false
		for i, s := range cfg.Services {
			if s.ID == id {
				found = true
				if update.Name != nil && *update.Name != "" {
					cfg.Services[i].Name = *update.Name
				}
				if update.Description != nil {
					cfg.Services[i].Description = *update.Description
				}
				if update.Host != nil && *update.Host != "" {
					if err := AssertAllowedHost(*update.Host); err != nil {
						return err
					}
					cfg.Services[i].Host = *update.Host
				}
				if update.Port != nil {
					if *update.Port < 1 || *update.Port > 65535 {
						return fmt.Errorf("port must be between 1 and 65535, got %d", *update.Port)
					}
					cfg.Services[i].Port = *update.Port
				}
				if update.Path != nil && *update.Path != "" {
					newPath := NormalizePath(*update.Path)
					if err := ValidatePath(newPath); err != nil {
						return fmt.Errorf("invalid service path: %w", err)
					}
					for j, other := range cfg.Services {
						if j != i && other.Path == newPath {
							return fmt.Errorf("service path %s already in use", newPath)
						}
					}
					cfg.Services[i].Path = newPath
				}
				if update.BackendPath != nil {
					cfg.Services[i].BackendPath = *update.BackendPath
				}
				if update.WebSocket != nil {
					cfg.Services[i].WebSocket = *update.WebSocket
				}
				if update.Category != nil {
					cfg.Services[i].Category = *update.Category
				}
				if update.BWLimit != nil {
					if *update.BWLimit < 0 {
						return fmt.Errorf("bwlimit must be >= 0 (bytes/sec), got %d", *update.BWLimit)
					}
					cfg.Services[i].BWLimit = *update.BWLimit
				}
				if update.RootAbsolute != nil {
					cfg.Services[i].RootAbsolute = *update.RootAbsolute
				}
				if update.Hostnames != nil {
					hostnames, err := ValidateHostnamesForUser(cfg.Services, id, *update.Hostnames)
					if err != nil {
						return err
					}
					cfg.Services[i].Hostnames = hostnames
				}
				if update.Kind != nil {
					kind, ok := NormalizeServiceKind(*update.Kind)
					if !ok {
						return fmt.Errorf("未知的服务类型 %q（可选 proxy / files）", *update.Kind)
					}
					cfg.Services[i].Kind = kind
				}
				if update.Root != nil {
					cfg.Services[i].Root = *update.Root
				}
				if update.ShowHidden != nil {
					cfg.Services[i].ShowHidden = *update.ShowHidden
				}
				// Resolve the kind last: it decides whether host:port or root is
				// authoritative, and a switch between them must leave the card in a
				// self-consistent state.
				kind, ok := NormalizeServiceKind(cfg.Services[i].Kind)
				if !ok {
					kind = ServiceKindProxy
				}
				cfg.Services[i].Kind = kind
				if kind == ServiceKindFiles {
					root, err := ValidateFileRoot(cfg.Services[i].Root, configPath)
					if err != nil {
						return err
					}
					cfg.Services[i].Root = root
					cfg.Services[i].Port = 0
					cfg.Services[i].BackendPath = ""
					cfg.Services[i].WebSocket = false
					cfg.Services[i].AuthBootstrap = nil
				} else {
					if err := AssertAllowedHost(cfg.Services[i].Host); err != nil {
						return err
					}
					if cfg.Services[i].Port < 1 || cfg.Services[i].Port > 65535 {
						return fmt.Errorf("port must be between 1 and 65535, got %d", cfg.Services[i].Port)
					}
					cfg.Services[i].Root = ""
					cfg.Services[i].ShowHidden = false
					// Validate the final host:port pair (both may have changed in
					// this same update) against routing back into the gateway.
					if err := AssertNotSelfTarget(cfg.Services[i].Host, cfg.Services[i].Port); err != nil {
						return err
					}
				}
				break
			}
		}
		if !found {
			return fmt.Errorf("service not found: %s", id)
		}

		raw, _ := loadRawConfig(configPath)
		raw["services"] = serializeServices(cfg.Services)
		return saveRawConfig(configPath, raw)
	})
}

// UpdateServicesLayout updates order and category for all services.
func UpdateServicesLayout(configPath string, items []LayoutItem) error {
	return withConfigLock(configPath, func() error {
		cfg, err := LoadUserConfig(configPath)
		if err != nil {
			return err
		}

		if len(items) != len(cfg.Services) {
			return fmt.Errorf("layout must include every service")
		}

		byID := make(map[string]*ServiceConfig)
		for i := range cfg.Services {
			byID[cfg.Services[i].ID] = &cfg.Services[i]
		}

		seen := make(map[string]bool)
		for _, item := range items {
			if seen[item.ID] {
				return fmt.Errorf("duplicate service in layout: %s", item.ID)
			}
			seen[item.ID] = true

			svc, ok := byID[item.ID]
			if !ok {
				return fmt.Errorf("service not found: %s", item.ID)
			}
			svc.Order = item.Order
			svc.Category = item.Category
		}

		raw, _ := loadRawConfig(configPath)
		raw["services"] = serializeServices(cfg.Services)
		return saveRawConfig(configPath, raw)
	})
}

type LayoutItem struct {
	ID       string `json:"id"`
	Order    int    `json:"order"`
	Category string `json:"category,omitempty"`
}

func serializeServices(services []ServiceConfig) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(services))
	for _, s := range services {
		m := map[string]interface{}{
			"id":   s.ID,
			"name": s.Name,
			"host": s.Host,
			"port": s.Port,
			"path": s.Path,
		}
		if s.Description != "" {
			m["description"] = s.Description
		}
		if s.BackendPath != "" {
			m["backend_path"] = s.BackendPath
		}
		if s.Category != "" {
			m["category"] = s.Category
		}
		if s.BWLimit > 0 {
			m["bwlimit"] = s.BWLimit
		}
		if s.AuthBootstrap != nil {
			m["auth_bootstrap"] = s.AuthBootstrap
		}
		if s.RootAbsolute {
			m["root_absolute"] = true
		}
		if len(s.Hostnames) > 0 {
			m["hostnames"] = s.Hostnames
		}
		if s.Kind == ServiceKindFiles {
			m["kind"] = ServiceKindFiles
			m["root"] = s.Root
			if s.ShowHidden {
				m["show_hidden"] = true
			}
		}
		m["websocket"] = s.WebSocket
		m["order"] = s.Order
		result = append(result, m)
	}
	return result
}

// DefaultCategory is the bucket for services without an explicit category.
// It is the single source of truth for the label: the web UI receives it in
// the boot payload so the client renders the same string.
const DefaultCategory = "未分类"

// GroupServicesByCategory groups services by category, ordered by each
// service's Order field. Category order follows the first (lowest-order)
// service seen, matching the client-side renderDashboard grouping: a stable
// sort by Order, then first-encounter category order. Ties on Order keep the
// input (config file) order, so the grouping is deterministic across map
// iteration and page loads.
func GroupServicesByCategory(services []ServiceConfig) []GroupedServices {
	sorted := make([]ServiceConfig, len(services))
	copy(sorted, services)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Order < sorted[j].Order })

	order := make([]string, 0)
	groups := make(map[string][]ServiceConfig)
	for _, s := range sorted {
		cat := s.Category
		if cat == "" {
			cat = DefaultCategory
		}
		if _, seen := groups[cat]; !seen {
			order = append(order, cat)
		}
		groups[cat] = append(groups[cat], s)
	}

	result := make([]GroupedServices, 0, len(order))
	for _, cat := range order {
		result = append(result, GroupedServices{
			Category: cat,
			Services: groups[cat],
		})
	}
	return result
}

type GroupedServices struct {
	Category string
	Services []ServiceConfig
}
