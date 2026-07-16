package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"gopkg.in/yaml.v3"
)

// ServiceConfig represents a single backend service.
type ServiceConfig struct {
	ID          string `yaml:"id" json:"id"`
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	Host        string `yaml:"host" json:"host"`
	Port        int    `yaml:"port" json:"port"`
	Path        string `yaml:"path" json:"path"`                               // Frontend path (e.g., /jupyter)
	BackendPath string `yaml:"backend_path,omitempty" json:"backend_path,omitempty"` // Backend path prefix (e.g., /app/index.html)
	WebSocket   bool   `yaml:"websocket" json:"websocket"`
	Category    string `yaml:"category,omitempty" json:"category,omitempty"`
	Order       int    `yaml:"order,omitempty" json:"order,omitempty"`
}

// UserConfig represents a user's configuration file.
type UserConfig struct {
	Auth     UserAuthConfig  `yaml:"auth"`
	Services []ServiceConfig `yaml:"services"`
}

type UserAuthConfig struct {
	PasswordHash string `yaml:"password_hash"`
}

// UserRecord contains a loaded user and their config path.
type UserRecord struct {
	Username   string
	ConfigPath string
	Config     UserConfig
}

func HashPassword(password string) string {
	h := sha256.Sum256([]byte(password))
	return hex.EncodeToString(h[:])
}

// IsWritable checks if the config file is writable by the current process.
// For shared gateway: group/others write bits. For self gateway: owner write bit.
func IsWritable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	mode := info.Mode().Perm()
	if mode&0222 != 0 {
		return true // group or others can write
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if stat.Uid == uint32(os.Getuid()) && mode&0200 != 0 {
			return true // process is owner and owner can write
		}
	}
	return false
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

func normalizePath(p string) string {
	return NormalizePath(p)
}

// EnsureUserConfig creates a default user config if it doesn't exist.
func EnsureUserConfig(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
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

	// Create with 0666 for shared gateway access
	if err := os.WriteFile(path, data, 0666); err != nil {
		return err
	}
	os.Chmod(path, 0666)
	fmt.Printf("[goprox] created user config: %s\n", path)
	fmt.Printf("[goprox] run \"goprox passwd\" to set your login password\n")
	return nil
}

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

	// Validate password hash
	if len(cfg.Auth.PasswordHash) != 64 {
		cfg.Auth.PasswordHash = "0000000000000000000000000000000000000000000000000000000000000000"
	}
	cfg.Auth.PasswordHash = strings.ToLower(cfg.Auth.PasswordHash)

	// Ensure services array is not nil
	if cfg.Services == nil {
		cfg.Services = []ServiceConfig{}
	}

	// Normalize service paths
	for i := range cfg.Services {
		cfg.Services[i].Path = normalizePath(cfg.Services[i].Path)
		if cfg.Services[i].Host == "" {
			cfg.Services[i].Host = "127.0.0.1"
		}
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
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	data, err := yaml.Marshal(raw)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0666); err != nil {
		return err
	}
	// Ensure 0666 regardless of umask
	os.Chmod(path, 0666)
	return nil
}

// UpdatePasswordHash updates only the password hash in a user config.
func UpdatePasswordHash(path, hash string) error {
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
}

// Config lock for safe concurrent writes
var configLocks sync.Map

func withConfigLock(path string, fn func() error) error {
	mu, _ := configLocks.LoadOrStore(path, &sync.Mutex{})
	m := mu.(*sync.Mutex)
	m.Lock()
	defer m.Unlock()
	return fn()
}

// AddService adds a new service to a user config.
func AddService(configPath string, svc ServiceConfig) error {
	return withConfigLock(configPath, func() error {
		cfg, err := LoadUserConfig(configPath)
		if err != nil {
			return err
		}

		// Check duplicate
		for _, s := range cfg.Services {
			if s.ID == svc.ID {
				return fmt.Errorf("service already exists: %s", svc.ID)
			}
		}

		if svc.Host == "" {
			svc.Host = "127.0.0.1"
		}
		if err := AssertAllowedHost(svc.Host); err != nil {
			return err
		}
		svc.Path = normalizePath(svc.Path)
		svc.WebSocket = svc.WebSocket != false // default true

		// Find next order
		maxOrder := -1
		for _, s := range cfg.Services {
			if s.Order > maxOrder {
				maxOrder = s.Order
			}
		}
		svc.Order = maxOrder + 1

		cfg.Services = append(cfg.Services, svc)

		raw, _ := loadRawConfig(configPath)
		services := serializeServices(cfg.Services)
		raw["services"] = services
		return saveRawConfig(configPath, raw)
	})
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
		return saveRawConfig(configPath, raw)
	})
}

// ServiceUpdate holds optional fields for updating a service.
type ServiceUpdate struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
	Host        *string `json:"host,omitempty"`
	Port        *int    `json:"port,omitempty"`
	Path        *string `json:"path,omitempty"`
	BackendPath *string `json:"backend_path,omitempty"`
	WebSocket   *bool   `json:"websocket,omitempty"`
	Category    *string `json:"category,omitempty"`
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
				if update.Port != nil && *update.Port > 0 {
					cfg.Services[i].Port = *update.Port
				}
				if update.Path != nil && *update.Path != "" {
					cfg.Services[i].Path = NormalizePath(*update.Path)
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
		m["websocket"] = s.WebSocket
		m["order"] = s.Order
		result = append(result, m)
	}
	return result
}

// GroupServicesByCategory groups services by category, sorted by order.
func GroupServicesByCategory(services []ServiceConfig) []GroupedServices {
	groups := make(map[string][]ServiceConfig)
	for _, s := range services {
		cat := s.Category
		if cat == "" {
			cat = "未分类"
		}
		groups[cat] = append(groups[cat], s)
	}

	// Calculate min order per group
	type groupInfo struct {
		name     string
		services []ServiceConfig
		minOrder int
	}
	infos := make([]groupInfo, 0, len(groups))
	for name, svcs := range groups {
		minOrder := 999999
		for _, s := range svcs {
			if s.Order < minOrder {
				minOrder = s.Order
			}
		}
		infos = append(infos, groupInfo{name, svcs, minOrder})
	}

	// Sort by minOrder
	for i := 0; i < len(infos); i++ {
		for j := i + 1; j < len(infos); j++ {
			if infos[i].minOrder > infos[j].minOrder {
				infos[i], infos[j] = infos[j], infos[i]
			}
		}
	}

	result := make([]GroupedServices, 0, len(infos))
	for _, info := range infos {
		// Sort within group by order
		svcs := info.services
		for i := 0; i < len(svcs); i++ {
			for j := i + 1; j < len(svcs); j++ {
				if svcs[i].Order > svcs[j].Order {
					svcs[i], svcs[j] = svcs[j], svcs[i]
				}
			}
		}
		result = append(result, GroupedServices{
			Category: info.name,
			Services: svcs,
		})
	}
	return result
}

type GroupedServices struct {
	Category string
	Services []ServiceConfig
}
