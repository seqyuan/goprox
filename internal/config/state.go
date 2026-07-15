package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type StateConfig struct {
	Server ServerState `yaml:"server"`
	Auth   AuthState   `yaml:"auth"`
	Users  UsersState  `yaml:"users"`
}

type ServerState struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

type AuthState struct {
	SessionSecret string `yaml:"session_secret"`
	SessionTTL    int    `yaml:"session_ttl"`
}

type UsersState struct {
	HomePrefix string `yaml:"home_prefix"`
	ScanHomes  bool   `yaml:"scan_homes"`
}

func defaultState() StateConfig {
	return StateConfig{
		Server: ServerState{
			Host: DefaultHost,
			Port: DefaultPort,
		},
		Auth: AuthState{
			SessionSecret: "",
			SessionTTL:    DefaultSessionTTL,
		},
		Users: UsersState{
			HomePrefix: HomePrefix(),
			ScanHomes:  true,
		},
	}
}

func EnsureState(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}

	s := defaultState()
	return writeStateFile(path, &s)
}

func LoadState(path string) (*StateConfig, error) {
	if err := EnsureState(path); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}

	var s StateConfig
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse state: %w", err)
	}

	// Apply defaults
	if s.Server.Host == "" {
		s.Server.Host = DefaultHost
	}
	if s.Server.Port == 0 {
		s.Server.Port = DefaultPort
	}
	if s.Auth.SessionTTL == 0 {
		s.Auth.SessionTTL = DefaultSessionTTL
	}
	if s.Users.HomePrefix == "" {
		s.Users.HomePrefix = HomePrefix()
	}

	// Generate session secret if empty
	if s.Auth.SessionSecret == "" {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, fmt.Errorf("generate session secret: %w", err)
		}
		s.Auth.SessionSecret = hex.EncodeToString(secret)

		// Persist it
		raw := make(map[string]interface{})
		raw["server"] = map[string]interface{}{
			"host": s.Server.Host,
			"port": s.Server.Port,
		}
		raw["auth"] = map[string]interface{}{
			"session_secret": s.Auth.SessionSecret,
			"session_ttl":    s.Auth.SessionTTL,
		}
		raw["users"] = map[string]interface{}{
			"home_prefix": s.Users.HomePrefix,
			"scan_homes":  s.Users.ScanHomes,
		}
		out, _ := yaml.Marshal(raw)
		os.WriteFile(path, out, 0644)
		fmt.Printf("[goprox] persisted generated session_secret to %s\n", path)
	}

	return &s, nil
}

func PersistServerConfig(path, host string, port int) error {
	// Load existing or create default
	var raw map[string]interface{}
	data, err := os.ReadFile(path)
	if err == nil {
		yaml.Unmarshal(data, &raw)
	}
	if raw == nil {
		raw = make(map[string]interface{})
	}

	server, ok := raw["server"].(map[string]interface{})
	if !ok {
		server = make(map[string]interface{})
	}
	if host != "" {
		server["host"] = host
	}
	if port > 0 {
		server["port"] = port
	}
	raw["server"] = server

	return writeStateFile(path, raw)
}

func writeStateFile(path string, v interface{}) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	data, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
