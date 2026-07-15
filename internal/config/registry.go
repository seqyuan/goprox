package config

import (
	"os"
	"strings"
	"sync"
	"time"
)

// UserRegistry scans and caches user configs from home directories.
type UserRegistry struct {
	state     *StateConfig
	users     map[string]*UserRecord
	mu        sync.RWMutex
	lastScan  time.Time
	scanEvery time.Duration
}

// NewUserRegistry creates a new registry.
func NewUserRegistry(state *StateConfig) *UserRegistry {
	return &UserRegistry{
		state:     state,
		users:     make(map[string]*UserRecord),
		scanEvery: 10 * time.Second,
	}
}

// Reload scans home directories for user configs.
func (r *UserRegistry) Reload() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.users = make(map[string]*UserRecord)

	if !r.state.Users.ScanHomes {
		return
	}

	homeRoot := r.state.Users.HomePrefix
	entries, err := os.ReadDir(homeRoot)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		username := entry.Name()
		if !IsValidUsername(username) {
			continue
		}

		configPath := GetUserConfigPath(username, homeRoot)
		if _, err := os.Stat(configPath); err != nil {
			continue
		}

		cfg, err := LoadUserConfig(configPath)
		if err != nil {
			continue
		}

		r.users[username] = &UserRecord{
			Username:   username,
			ConfigPath: configPath,
			Config:     *cfg,
		}
	}

	r.lastScan = time.Now()
}

// EnsureFresh reloads if enough time has passed.
func (r *UserRegistry) EnsureFresh() {
	if time.Since(r.lastScan) > r.scanEvery {
		r.Reload()
	}
}

// GetUser returns a user record by username.
func (r *UserRegistry) GetUser(username string) *UserRecord {
	r.EnsureFresh()
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.users[username]
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

	configPath := GetUserConfigPath(username, r.state.Users.HomePrefix)
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
	r.mu.RLock()
	defer r.mu.RUnlock()

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

	user := r.users[username]
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
	r.mu.RLock()
	defer r.mu.RUnlock()

	user := r.users[username]
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
