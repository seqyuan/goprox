package config

import (
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// UserRegistry scans and caches user configs from the config directory.
type UserRegistry struct {
	configDir     string
	users         map[string]*UserRecord
	hosts         map[string]*HostTarget
	hostConflicts map[string][]string
	mu            sync.RWMutex
	lastScan      time.Time
	scanEvery     time.Duration
}

// HostTarget maps a virtual hostname to the owning user's service.
type HostTarget struct {
	Username string
	Service  *ServiceConfig
}

// HostEntry is a read-only summary used by `goprox check`.
type HostEntry struct {
	Host      string
	Username  string
	ServiceID string
}

// NewUserRegistry creates a new registry scanning configDir/users/*.yaml.
func NewUserRegistry(configDir string) *UserRegistry {
	return &UserRegistry{
		configDir:     configDir,
		users:         make(map[string]*UserRecord),
		hosts:         make(map[string]*HostTarget),
		hostConflicts: make(map[string][]string),
		scanEvery:     10 * time.Second,
	}
}

// Reload scans the config/users directory for user configs.
// The registry map is only swapped in after a fully successful scan, so a
// transient read error keeps the previous snapshot instead of dropping all users.
func (r *UserRegistry) Reload() {
	usersDir := UsersDir(r.configDir)
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		// A fresh install has no users directory until the first `goprox user`
		// command, so a missing directory is a normal empty state. For any
		// error (including missing) still advance lastScan: otherwise
		// EnsureFresh sees the zero timestamp and retries the scan on every
		// single request, flooding the log and the filesystem.
		if !os.IsNotExist(err) {
			log.Printf("[goprox] scan %s: %v", usersDir, err)
		}
		r.mu.Lock()
		r.lastScan = time.Now()
		r.mu.Unlock()
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

	newHosts, hostConflicts := buildHostIndex(newUsers)
	for host, owners := range hostConflicts {
		key := "host-conflict:" + host
		if _, loaded := warnedHostConflicts.LoadOrStore(key, struct{}{}); !loaded {
			log.Printf("[goprox] virtual host %q is configured by multiple services/users %v; disabled", host, owners)
		}
	}

	r.mu.Lock()
	r.users = newUsers
	r.hosts = newHosts
	r.hostConflicts = hostConflicts
	r.lastScan = time.Now()
	r.mu.Unlock()
}

// warnedHostConflicts de-duplicates periodic-reload warnings.
var warnedHostConflicts sync.Map

// buildHostIndex maps every unique hostname to its service. A hostname
// claimed by more than one service (across all users) is removed from the
// routable index and reported as a conflict.
func buildHostIndex(users map[string]*UserRecord) (map[string]*HostTarget, map[string][]string) {
	type candidate struct {
		target *HostTarget
		count  int
		owners map[string]bool // "username/serviceID", for actionable errors
	}
	candidates := make(map[string]*candidate)
	for username, user := range users {
		for i := range user.Config.Services {
			svc := &user.Config.Services[i]
			for _, host := range svc.Hostnames {
				c := candidates[host]
				if c == nil {
					c = &candidate{
						target: &HostTarget{Username: username, Service: svc},
						owners: make(map[string]bool),
					}
					candidates[host] = c
				}
				c.count++
				c.owners[username+"/"+svc.ID] = true
			}
		}
	}

	hosts := make(map[string]*HostTarget, len(candidates))
	conflicts := make(map[string][]string)
	for host, c := range candidates {
		if c.count == 1 {
			hosts[host] = c.target
			continue
		}
		owners := make([]string, 0, len(c.owners))
		for owner := range c.owners {
			owners = append(owners, owner)
		}
		sort.Strings(owners)
		conflicts[host] = owners
	}
	return hosts, conflicts
}

// FindByHost looks up a virtual hostname in the current registry snapshot.
func (r *UserRegistry) FindByHost(host string) *HostTarget {
	r.EnsureFresh()
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.hosts[host]
}

// HostEntries returns the routable host index sorted by hostname.
func (r *UserRegistry) HostEntries() []HostEntry {
	r.EnsureFresh()
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]HostEntry, 0, len(r.hosts))
	for host, target := range r.hosts {
		out = append(out, HostEntry{
			Host:      host,
			Username:  target.Username,
			ServiceID: target.Service.ID,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

// HostOwners returns the "username/serviceID" owners of host, excluding one
// service (used when validating an update). It scans all users, including
// hosts currently disabled by a conflict, so a bad edit cannot hide behind
// the routable index.
func (r *UserRegistry) HostOwners(host, excludeUser, excludeServiceID string) []string {
	r.EnsureFresh()
	r.mu.RLock()
	defer r.mu.RUnlock()
	var owners []string
	for username, record := range r.users {
		for i := range record.Config.Services {
			svc := &record.Config.Services[i]
			if username == excludeUser && svc.ID == excludeServiceID {
				continue
			}
			for _, h := range svc.Hostnames {
				if h == host {
					owners = append(owners, username+"/"+svc.ID)
					break
				}
			}
		}
	}
	sort.Strings(owners)
	return owners
}

// HasHosts reports whether any virtual hostname is currently routable.
func (r *UserRegistry) HasHosts() bool {
	r.EnsureFresh()
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.hosts) > 0
}

// ValidateHosts returns an error when any hostname is claimed by more than one
// service. It is intended for startup validation, where fail-fast is safer
// than silently routing to one of the claimants.
func (r *UserRegistry) ValidateHosts() error {
	r.EnsureFresh()
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.hostConflicts) == 0 {
		return nil
	}
	lines := make([]string, 0, len(r.hostConflicts))
	for host, owners := range r.hostConflicts {
		lines = append(lines, fmt.Sprintf("%s (%s)", host, strings.Join(owners, ", ")))
	}
	sort.Strings(lines)
	return fmt.Errorf("duplicate virtual hostnames: %s", strings.Join(lines, "; "))
}

// EnsureFresh reloads if enough time has passed. lastScan is written under
// the registry lock by Reload; read it under RLock so concurrent vhost/path
// lookups do not race with the scanner.
func (r *UserRegistry) EnsureFresh() {
	r.mu.RLock()
	last := r.lastScan
	r.mu.RUnlock()
	if time.Since(last) > r.scanEvery {
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
