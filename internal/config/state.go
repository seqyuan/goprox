package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type StateConfig struct {
	Server ServerState `yaml:"server"`
	Auth   AuthState   `yaml:"auth"`
	SSO    SSOState    `yaml:"sso"`
}

// SSOState configures the lightweight single sign-on layer: the gateway
// authenticates the user once and vouches for their identity to proxied
// backends by setting a request header on every forwarded request.
//
//   - UserHeader: name of the header carrying the logged-in username
//     (e.g. X-Authenticated-User). Empty disables the feature.
//   - HMACSecret: optional shared secret. When set, every forwarded request
//     also carries UserHeader+"-Signature": an HMAC-SHA256 of
//     "goprox-sso:v1:"+username (base64url, unpadded) that backends can
//     verify without relying on network isolation alone.
//
// Security note: the header is the backend's only proof of identity, so the
// backend must be reachable only through the gateway (loopback/firewall).
// A directly reachable backend could be impersonated with a forged header;
// HMACSecret fixes that even when the backend cannot be network-isolated.
type SSOState struct {
	UserHeader string `yaml:"user_header,omitempty"`
	HMACSecret string `yaml:"hmac_secret,omitempty"`
}

// IsValidHeaderName reports whether s is a valid HTTP header field name
// (RFC 7230 token). http.Header.Set panics on invalid names, so the name is
// validated at configuration time and guarded again before every use.
func IsValidHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		if strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0 {
			continue
		}
		return false
	}
	return true
}

type ServerState struct {
	Host         string `yaml:"host"`
	Port         int    `yaml:"port"`
	TrustedProxy string `yaml:"trusted_proxy,omitempty"` // CIDR of a trusted reverse proxy; enables X-Forwarded-* header trust
	Title        string `yaml:"title,omitempty"`         // site title shown in the top-left corner (default: GoProx)
	// Native TLS termination. When both are set the gateway serves HTTPS,
	// making the whole site a secure context (all Web Crypto / secure-context
	// APIs become available to proxied apps). Paths are stored as given;
	// --tls-selfsigned writes absolute paths into the config dir.
	TLSCert string `yaml:"tls_cert,omitempty"`
	TLSKey  string `yaml:"tls_key,omitempty"`
	// PublicHost is the gateway's externally visible authority
	// (host or host:port), used to build absolute login redirects for
	// virtual-host services.
	PublicHost string `yaml:"public_host,omitempty"`
	// PublicScheme is "http" or "https"; when empty the gateway infers it
	// from TLS / trusted-proxy X-Forwarded-Proto.
	PublicScheme string `yaml:"public_scheme,omitempty"`
	// CookieDomain makes the session cookie shared across service subdomains
	// (e.g. ".gw.example.com"). Required when any service declares hostnames.
	CookieDomain string `yaml:"cookie_domain,omitempty"`
}

type AuthState struct {
	SessionSecret string `yaml:"session_secret"`
	SessionTTL    int    `yaml:"session_ttl"`
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
	}
}

func EnsureState(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
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

	if s.Server.PublicHost, err = NormalizePublicHost(s.Server.PublicHost); err != nil {
		return nil, err
	}
	if s.Server.PublicScheme, err = NormalizePublicScheme(s.Server.PublicScheme); err != nil {
		return nil, err
	}
	if s.Server.CookieDomain, err = NormalizeCookieDomain(s.Server.CookieDomain); err != nil {
		return nil, err
	}

	// A hand-edited user_header must be a valid header name; anything else
	// would panic http.Header.Set on every proxied request.
	if s.SSO.UserHeader != "" && !IsValidHeaderName(s.SSO.UserHeader) {
		fmt.Printf("[goprox] WARNING: ignoring invalid sso.user_header %q (must be a valid HTTP header name)\n", s.SSO.UserHeader)
		s.SSO.UserHeader = ""
		s.SSO.HMACSecret = ""
	}

	// Generate session secret if empty
	if s.Auth.SessionSecret == "" {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, fmt.Errorf("generate session secret: %w", err)
		}
		s.Auth.SessionSecret = hex.EncodeToString(secret)

		// Persist it. If this fails, silently continuing would generate a new
		// secret on every restart and invalidate every session, so surface the
		// error and refuse to start with an ephemeral secret.
		if err := writeStateFile(path, &s); err != nil {
			return nil, fmt.Errorf("persist generated session_secret to %s: %w", path, err)
		}
		fmt.Printf("[goprox] persisted generated session_secret to %s\n", path)
	}

	return &s, nil
}

func PersistServerConfig(path, host string, port int, trustedProxy, title, tlsCert, tlsKey, publicHost, publicScheme, cookieDomain string) error {
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
	if trustedProxy != "" {
		server["trusted_proxy"] = trustedProxy
	}
	if title != "" {
		server["title"] = title
	}
	if tlsCert != "" {
		server["tls_cert"] = tlsCert
	}
	if tlsKey != "" {
		server["tls_key"] = tlsKey
	}
	if publicHost != "" {
		server["public_host"] = publicHost
	}
	if publicScheme != "" {
		server["public_scheme"] = publicScheme
	}
	if cookieDomain != "" {
		server["cookie_domain"] = cookieDomain
	}
	raw["server"] = server

	return writeStateFile(path, raw)
}

// PersistSSOConfig writes the sso section of state.yaml. Pass empty strings
// to disable SSO.
func PersistSSOConfig(path, userHeader, hmacSecret string) error {
	var raw map[string]interface{}
	data, err := os.ReadFile(path)
	if err == nil {
		yaml.Unmarshal(data, &raw)
	}
	if raw == nil {
		raw = make(map[string]interface{})
	}
	raw["sso"] = map[string]interface{}{
		"user_header": userHeader,
		"hmac_secret": hmacSecret,
	}
	return writeStateFile(path, raw)
}

func writeStateFile(path string, v interface{}) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	// 0600: state.yaml holds the session_secret.
	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}
