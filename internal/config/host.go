package config

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// hostLabelRe matches a single DNS label. Hostnames are normalized to
// lowercase before validation, so uppercase input is accepted.
var hostLabelRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// NormalizeHostname validates a virtual-host DNS name (no scheme, port, path
// or wildcard) and returns its lowercase form without a trailing dot.
func NormalizeHostname(host string) (string, error) {
	host = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(host, ".")))
	if host == "" {
		return "", fmt.Errorf("empty hostname")
	}
	if strings.ContainsAny(host, "/:@*? \t\r\n") {
		return "", fmt.Errorf("hostname %q contains invalid characters", host)
	}
	if net.ParseIP(host) != nil {
		return "", fmt.Errorf("hostname %q is an IP address; use a DNS name", host)
	}
	if len(host) > 253 {
		return "", fmt.Errorf("hostname %q is too long", host)
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("hostname %q must contain at least two labels", host)
	}
	for _, label := range labels {
		if !hostLabelRe.MatchString(label) {
			return "", fmt.Errorf("hostname %q has invalid label %q", host, label)
		}
	}
	return host, nil
}

// NormalizeHostnames normalizes and de-duplicates a service's hostnames,
// returning the dropped invalid entries for a one-time warning.
func NormalizeHostnames(in []string) (out []string, dropped []string) {
	out = make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, raw := range in {
		host, err := NormalizeHostname(raw)
		if err != nil {
			dropped = append(dropped, raw)
			continue
		}
		if seen[host] {
			continue
		}
		seen[host] = true
		out = append(out, host)
	}
	return out, dropped
}

// HostFromHostPort extracts the host part of an HTTP Host header or an
// authority string, stripping an optional port and brackets. It does not
// require a DNS name (requests may legitimately use an IP).
func HostFromHostPort(hostport string) string {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		hostport = host
	} else {
		hostport = strings.Trim(hostport, "[]")
	}
	return strings.ToLower(strings.TrimSuffix(hostport, "."))
}

// NormalizePublicHost validates the gateway's public authority
// (host or host:port) used to build absolute login URLs.
func NormalizePublicHost(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if strings.ContainsAny(value, "/?#@ \t\r\n") {
		return "", fmt.Errorf("public_host must be a host or host:port")
	}

	host, port := value, ""
	if h, p, err := net.SplitHostPort(value); err == nil {
		host, port = h, p
	} else if strings.Count(value, ":") == 1 {
		// A single colon is either host:port; SplitHostPort would have
		// succeeded for a valid bracket-free host, so this is malformed.
		return "", fmt.Errorf("invalid public_host %q", value)
	}

	host, err := NormalizeHostname(host)
	if err != nil {
		return "", fmt.Errorf("public_host: %w", err)
	}
	if port == "" {
		return host, nil
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return "", fmt.Errorf("public_host: invalid port %q", port)
	}
	return net.JoinHostPort(host, port), nil
}

// NormalizePublicScheme validates server.public_scheme.
func NormalizePublicScheme(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "", nil
	}
	if value != "http" && value != "https" {
		return "", fmt.Errorf("public_scheme must be http or https")
	}
	return value, nil
}

// NormalizeCookieDomain validates the parent domain used for the shared
// session cookie (e.g. ".gw.example.com").
func NormalizeCookieDomain(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(value, ".")))
	if value == "" {
		return "", nil
	}
	if !strings.HasPrefix(value, ".") {
		return "", fmt.Errorf("cookie_domain must start with '.' (e.g. .example.com)")
	}
	base := strings.TrimPrefix(value, ".")
	if net.ParseIP(base) != nil {
		return "", fmt.Errorf("cookie_domain must be a DNS parent domain, not an IP")
	}
	labels := strings.Split(base, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("cookie_domain must be a parent domain like .example.com")
	}
	for _, label := range labels {
		if !hostLabelRe.MatchString(label) {
			return "", fmt.Errorf("cookie_domain has invalid label %q", label)
		}
	}
	return "." + strings.Join(labels, "."), nil
}

// HostWithinCookieDomain reports whether host is covered by a parent cookie
// domain such as ".example.com". An empty domain disables the check.
func HostWithinCookieDomain(host, domain string) bool {
	if domain == "" {
		return true
	}
	d := strings.TrimPrefix(strings.ToLower(strings.TrimSuffix(domain, ".")), ".")
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	return h == d || strings.HasSuffix(h, "."+d)
}
