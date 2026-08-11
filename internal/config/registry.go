package config

import (
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// UserRegistry scans and caches user configs from the config directory.
type UserRegistry struct {
	configDir string
	users     map[string]*UserRecord
	mu        sync.RWMutex
	lastScan  time.Time
	scanEvery time.Duration
}

// NewUserRegistry creates a new registry scanning configDir/users/*.yaml.
func NewUserRegistry(configDir string) *UserRegistry {
	return &UserRegistry{
		configDir: configDir,
		users:     make(map[string]*UserRecord),
		scanEvery: 10 * time.Second,
	}
}

// Reload scans the config/users directory for user configs.
// The registry map is only swapped in after a fully successful scan, so a
// transient read error keeps the previous snapshot instead of dropping all users.
func (r *UserRegistry) Reload() {
	usersDir := UsersDir(r.configDir)
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		log.Printf("[goprox] scan %s: %v", usersDir, err)
		return
	}

	newUsers := make(map[string]*UserRecord, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yaml") {
			continue
		}
		username := strings.TrimSuffix(name, ".yaml")
		if !IsValidUsername(username) {
			continue
		}

		configPath := UserConfigPath(r.configDir, username)
		cfg, err := LoadUserConfig(configPath)
		if err != nil {
			log.Printf("[goprox] skip user %s: %v", username, err)
			continue
		}

		newUsers[username] = &UserRecord{
			Username:   username,
			ConfigPath: configPath,
			Config:     *cfg,
		}
	}

	r.mu.Lock()
	r.users = newUsers
	r.lastScan = time.Now()
	r.mu.Unlock()
}

// EnsureFresh reloads if enough time has passed.
func (r *UserRegistry) EnsureFresh() {
	if time.Since(r.lastScan) > r.scanEvery {
		r.Reload()
	}
}

// GetUser returns a user record by username.
// If the user is not in the cache, tries to load them on-demand.
func (r *UserRegistry) GetUser(username string) *UserRecord {
	r.EnsureFresh()

	r.mu.RLock()
	user := r.users[username]
	r.mu.RUnlock()

	if user != nil {
		return user
	}

	// Cache miss: try loading this user directly
	return r.loadUser(username)
}

// loadUser loads a single user config from the filesystem directly.
func (r *UserRegistry) loadUser(username string) *UserRecord {
	if !IsValidUsername(username) {
		return nil
	}

	configPath := UserConfigPath(r.configDir, username)
	if _, err := os.Stat(configPath); err != nil {
		return nil
	}

	cfg, err := LoadUserConfig(configPath)
	if err != nil {
		return nil
	}

	record := &UserRecord{
		Username:   username,
		ConfigPath: configPath,
		Config:     *cfg,
	}

	// Insert into cache for subsequent lookups
	r.mu.Lock()
	r.users[username] = record
	r.mu.Unlock()

	return record
}

// ListUsers returns all loaded users.
func (r *UserRegistry) ListUsers() []*UserRecord {
	r.EnsureFresh()
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]*UserRecord, 0, len(r.users))
	for _, u := range r.users {
		result = append(result, u)
	}
	return result
}

// GetUserConfigForLogin loads a user config directly for login verification.
func (r *UserRegistry) GetUserConfigForLogin(username string) *UserConfig {
	if !IsValidUsername(username) {
		return nil
	}

	configPath := UserConfigPath(r.configDir, username)
	if _, err := os.Stat(configPath); err != nil {
		return nil
	}

	cfg, err := LoadUserConfig(configPath)
	if err != nil {
		return nil
	}
	return cfg
}

// ServiceMatch holds a matched service from a proxy path.
type ServiceMatch struct {
	Username      string
	Service       *ServiceConfig
	RemainingPath string
	Legacy        bool
}

// FindService finds a service matching /proxy/{user}/{service}/...
func (r *UserRegistry) FindService(requestPath string) *ServiceMatch {
	r.EnsureFresh()

	prefix := "/proxy/"
	if !strings.HasPrefix(requestPath, prefix) {
		return nil
	}

	rest := requestPath[len(prefix):]
	slashIdx := strings.Index(rest, "/")
	if slashIdx <= 0 {
		return nil
	}

	username := rest[:slashIdx]
	if !IsValidUsername(username) {
		return nil
	}

	user := r.GetUser(username)
	if user == nil {
		return nil
	}

	pathAfterUser := rest[slashIdx:]
	if pathAfterUser == "" {
		pathAfterUser = "/"
	}

	var bestMatch *ServiceMatch
	bestLen := -1

	for i := range user.Config.Services {
		svc := &user.Config.Services[i]
		sp := svc.Path
		if pathAfterUser == sp || strings.HasPrefix(pathAfterUser, sp+"/") {
			if len(sp) > bestLen {
				bestLen = len(sp)
				remaining := pathAfterUser[len(sp):]
				if remaining == "" {
					remaining = "/"
				}
				bestMatch = &ServiceMatch{
					Username:      username,
					Service:       svc,
					RemainingPath: remaining,
				}
			}
		}
	}

	return bestMatch
}

// FindLegacyService finds a service via legacy /proxy{path} format.
func (r *UserRegistry) FindLegacyService(requestPath, username string) *ServiceMatch {
	r.EnsureFresh()

	user := r.GetUser(username)
	if user == nil {
		return nil
	}

	prefix := "/proxy/"
	if !strings.HasPrefix(requestPath, prefix) {
		return nil
	}

	var bestMatch *ServiceMatch
	bestLen := -1

	for i := range user.Config.Services {
		svc := &user.Config.Services[i]
		legacyPrefix := "/proxy" + svc.Path
		if requestPath == legacyPrefix ||
			strings.HasPrefix(requestPath, legacyPrefix+"/") ||
			strings.HasPrefix(requestPath, legacyPrefix+"?") {
			if len(svc.Path) <= bestLen {
				continue
			}
			remaining := requestPath[len(legacyPrefix):]
			if remaining != "" && !strings.HasPrefix(remaining, "/") && !strings.HasPrefix(remaining, "?") {
				continue
			}
			if remaining == "" {
				remaining = "/"
			}
			bestLen = len(svc.Path)
			bestMatch = &ServiceMatch{
				Username:      username,
				Service:       svc,
				RemainingPath: remaining,
				Legacy:        true,
			}
		}
	}

	return bestMatch
}

// FindServiceForUser tries multi-user then legacy paths.
func (r *UserRegistry) FindServiceForUser(requestPath, sessionUser string) *ServiceMatch {
	if m := r.FindService(requestPath); m != nil {
		return m
	}
	return r.FindLegacyService(requestPath, sessionUser)
}

// UsernameFromProxyPath extracts username from /proxy/{user}/... path.
func UsernameFromProxyPath(requestPath string) string {
	prefix := "/proxy/"
	if !strings.HasPrefix(requestPath, prefix) {
		return ""
	}
	rest := requestPath[len(prefix):]
	slashIdx := strings.Index(rest, "/")
	if slashIdx <= 0 {
		return ""
	}
	username := rest[:slashIdx]
	if !IsValidUsername(username) {
		return ""
	}
	return username
}
