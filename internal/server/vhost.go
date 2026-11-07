package server

// 独立域名虚拟主机：Host 索引校验、登录跳转与根路径直通。

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/seqyuan/goprox/internal/auth"
	"github.com/seqyuan/goprox/internal/config"
	"github.com/seqyuan/goprox/internal/proxy"
	"github.com/seqyuan/goprox/internal/web"
)

func (s *Server) ValidateVHosts() error {
	if err := s.registry.ValidateHosts(); err != nil {
		return err
	}
	if !s.registry.HasHosts() {
		return nil
	}
	if s.publicHost == "" {
		return fmt.Errorf("server.public_host is required when services declare hostnames")
	}
	if s.cookieDomain == "" {
		return fmt.Errorf("server.cookie_domain is required when services declare hostnames")
	}
	publicHost := config.HostFromHostPort(s.publicHost)
	if target := s.registry.FindByHost(publicHost); target != nil {
		return fmt.Errorf("server.public_host %q is also configured as a service hostname", s.publicHost)
	}
	if !config.HostWithinCookieDomain(publicHost, s.cookieDomain) {
		return fmt.Errorf("server.public_host %q is not covered by cookie_domain %q", publicHost, s.cookieDomain)
	}
	for _, user := range s.registry.ListUsers() {
		for _, svc := range user.Config.Services {
			for _, host := range svc.Hostnames {
				if !config.HostWithinCookieDomain(host, s.cookieDomain) {
					return fmt.Errorf("service %q hostname %q is not covered by cookie_domain %q", svc.ID, host, s.cookieDomain)
				}
			}
		}
	}
	if s.publicScheme != "https" && s.state.Server.TLSCert == "" {
		log.Printf("[goprox] WARNING: virtual hosts are enabled without HTTPS; parent-domain session cookies will be sent over HTTP")
	}
	return nil
}

// publicSchemeFor returns the scheme used to build absolute login redirects.

func (s *Server) publicSchemeFor(r *http.Request) string {
	if s.publicScheme != "" {
		return s.publicScheme
	}
	if s.state.Server.TLSCert != "" || auth.IsSecureRequest(r) {
		return "https"
	}
	return "http"
}

// publicAuthority returns the main gateway authority for absolute URLs. When
// public_host has no port, reuse the port the browser used for the service
// host (nonstandard ports), so local/LAN deployments do not lose it.

func (s *Server) publicAuthority(r *http.Request) string {
	if s.publicHost == "" {
		return ""
	}
	if !strings.Contains(s.publicHost, ":") {
		if _, port, err := net.SplitHostPort(r.Host); err == nil && port != "" && port != "80" && port != "443" {
			return net.JoinHostPort(s.publicHost, port)
		}
	}
	return s.publicHost
}

// handleVirtualHost serves a request addressed to one of the configured
// service hostnames. It returns false for unknown hosts so they fall through
// to the existing path-based mux.

func (s *Server) handleVirtualHost(w http.ResponseWriter, r *http.Request) bool {
	host := config.HostFromHostPort(r.Host)
	if host == "" {
		return false
	}
	target := s.registry.FindByHost(host)
	if target == nil || target.Service == nil {
		return false
	}

	session := s.sessionFromCookies(r.Header.Get("Cookie"))
	if !session.Valid || session.UserID == "" {
		// Browser navigations get the main login redirect; API/XHR clients
		// get a 401 instead of a 302 to HTML, which they cannot parse.
		if !wantsHTML(r) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return true
		}
		s.redirectToMainLogin(w, r)
		return true
	}
	if session.UserID != target.Username {
		// Hide the existence of another user's vhost.
		sendHTML(w, http.StatusNotFound, web.NotFoundPage(s.siteTitle))
		return true
	}
	if auth.ShouldRefreshSession(session, s.state.Auth.SessionTTL) {
		secure := auth.IsSecureRequest(r)
		w.Header().Add("Set-Cookie", s.issueSessionCookie(session.UserID, secure))
	}
	s.proxyVHost(w, r, target)
	return true
}

// redirectToMainLogin sends an unauthenticated service-host request to the
// main gateway login, preserving the original absolute URL for the return.

func (s *Server) redirectToMainLogin(w http.ResponseWriter, r *http.Request) {
	scheme := s.publicSchemeFor(r)
	main := s.publicAuthority(r)
	if main == "" {
		http.Error(w, "virtual-host login is not configured", http.StatusInternalServerError)
		return
	}
	next := scheme + "://" + r.Host + r.URL.RequestURI()
	login := scheme + "://" + main + "/login?next=" + url.QueryEscape(next)
	if s.cookieDomain != "" {
		// Drop a stale host-only session cookie on this service host; the
		// parent-domain cookie is unaffected.
		w.Header().Add("Set-Cookie", s.cookieNames.ClearSessionCookie())
	}
	http.Redirect(w, r, login, http.StatusFound)
}

// proxyVHost forwards a request to a service that owns its hostname. The
// backend receives the browser path unchanged; no route cookies or /proxy
// prefix rewriting are involved.

func (s *Server) proxyVHost(w http.ResponseWriter, r *http.Request, target *config.HostTarget) {
	if isWebSocketUpgrade(r) && !target.Service.WebSocket {
		http.Error(w, "WebSocket not enabled for this service", http.StatusForbidden)
		return
	}
	fc := proxy.BuildProxyForwardContext(r, target.Username, target.Service.Path, false)
	fc.SSO = s.state.SSO
	fc.Mode = proxy.ForwardVHost
	fc.Base = proxy.BaseForPath("", r.URL.Path)
	s.forwardToBackend(w, r, target.Service, fc)
}

// handleBackendLogin detects POST /login from a proxied backend (e.g. Jupyter login form).
// If the user already has a valid session and the Referer or route cookie points to a
// backend service, the request is forwarded there instead of being handled by goprox.
