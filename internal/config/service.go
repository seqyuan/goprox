package config

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

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

type AuthBootstrapConfig struct {
	Mode       string `yaml:"mode" json:"mode"`                       // static | file | log
	Param      string `yaml:"param,omitempty" json:"param,omitempty"` // query param name, default "token"
	TokenValue string `yaml:"token_value,omitempty" json:"token_value,omitempty"`
	TokenFile  string `yaml:"token_file,omitempty" json:"token_file,omitempty"`
	TokenLog   string `yaml:"token_log,omitempty" json:"token_log,omitempty"`
	TokenRegex string `yaml:"token_regex,omitempty" json:"token_regex,omitempty"`
}

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
			root, err := ValidateFileRoot(svc.Root, configPath, cfg.FilesRoots)
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
					root, err := ValidateFileRoot(cfg.Services[i].Root, configPath, cfg.FilesRoots)
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

const (
	ServiceKindProxy = "proxy"
	ServiceKindFiles = "files"
)

// NormalizeServiceKind validates a service kind. An empty value means the
// default (proxy); ok is false for an unrecognized kind.

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

// ValidatePath checks a normalized path for characters safe to use in URLs,
// <base href> injection, and cookie values. Empty string is valid (means
// "auto-generate"). "/" is valid (root). Returns an error otherwise.

// LoadUserConfig loads a user config from a path.

const DefaultCategory = "未分类"

// GroupServicesByCategory groups services by category, ordered by each
// service's Order field. Category order follows the first (lowest-order)
// service seen, matching the client-side renderDashboard grouping: a stable
// sort by Order, then first-encounter category order. Ties on Order keep the
// input (config file) order, so the grouping is deterministic across map
// iteration and page loads.
