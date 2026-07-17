package server

import (
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	"github.com/seqyuan/goprox/internal/api"
	"github.com/seqyuan/goprox/internal/auth"
	"github.com/seqyuan/goprox/internal/config"
	"github.com/seqyuan/goprox/internal/proxy"
	"github.com/seqyuan/goprox/internal/rate"
	"github.com/seqyuan/goprox/internal/web"
)

const loginErrorMsg = "用户名或密码错误"

// Server is the main GoProx HTTP server.
type Server struct {
	state         *config.StateConfig
	registry      *config.UserRegistry
	sessionSecret string
	loginLimiter  *rate.Limiter
	apiHandler    *api.Handler
}

// New creates a new Server from state config.
func New(state *config.StateConfig) *Server {
	registry := config.NewUserRegistry(state)
	registry.Reload()

	return &Server{
		state:         state,
		registry:      registry,
		sessionSecret: state.Auth.SessionSecret,
		loginLimiter:  rate.NewLimiter(10, 15*time.Minute),
		apiHandler:    api.NewHandler(registry, state.Auth.SessionSecret),
	}
}

// Handler returns the HTTP handler for the server.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// API routes (handled by api.Handler)
	// Use specific exact matches to avoid conflicts with backend service APIs
	mux.HandleFunc("/api/services", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" || r.Method == "POST" {
			s.apiHandler.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})

	mux.HandleFunc("/api/services/", func(w http.ResponseWriter, r *http.Request) {
		// Handle /api/services/{id} and /api/services/layout
		path := r.URL.Path
		if path == "/api/services/layout" || strings.HasPrefix(path, "/api/services/") {
			if s.apiHandler.ServeHTTP(w, r) {
				return
			}
		}
		// Not a goprox API: try forwarding to backend service
		if s.handleRouteCookieProxy(w, r) {
			return
		}
		if s.handleRefererProxy(w, r) {
			return
		}
		http.NotFound(w, r)
	})

	// Other /api/* paths: forward to backend services (e.g., Next.js API routes)
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		// Skip if it's a goprox API path (already handled above)
		if r.URL.Path == "/api/services" || strings.HasPrefix(r.URL.Path, "/api/services/") {
			http.NotFound(w, r)
			return
		}
		// Try to forward to backend service
		if s.handleRouteCookieProxy(w, r) {
			return
		}
		if s.handleRefererProxy(w, r) {
			return
		}
		http.NotFound(w, r)
	})

	// Favicon
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write([]byte(web.FaviconSVG()))
	})

	// Logout
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", auth.ClearSessionCookie())
		http.Redirect(w, r, "/", http.StatusFound)
	})

	// Login
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			if s.handleBackendLogin(w, r) {
				return
			}
			s.handleLogin(w, r)
			return
		}
		// GET /login: may be a backend service login page (e.g. AnnoVibe redirect)
		if s.handleRouteCookieProxy(w, r) {
			return
		}
		if s.handleRefererProxy(w, r) {
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
	})

	// Proxy routes
	mux.HandleFunc("/proxy/", func(w http.ResponseWriter, r *http.Request) {
		s.handleProxy(w, r)
	})

	// Root route (dashboard/login page)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			if s.handleRouteCookieProxy(w, r) {
				return
			}
			if s.handleRefererProxy(w, r) {
				return
			}
			session := auth.GetSessionFromCookies(r.Header.Get("Cookie"), s.sessionSecret)
			if session.Valid && session.UserID != "" && r.Method == "GET" {
				if s.redirectBareService(w, r, session.UserID) {
					return
				}
			}
			sendHTML(w, 404, web.NotFoundPage())
			return
		}
		// GET / is the GoProx dashboard. Only a clear backend referer may route it.
		if s.handleRefererProxy(w, r) {
			return
		}
		// If the user landed on /?xxx (e.g. /?refresh=1) after escaping the proxy
		// prefix, try to redirect them back via the route cookie.
		if r.URL.RawQuery != "" {
			session := auth.GetSessionFromCookies(r.Header.Get("Cookie"), s.sessionSecret)
			if session.Valid && session.UserID != "" {
				route := auth.GetRouteCookieForRequest(
					r.Header.Get("Cookie"), "", r.Header.Get("Referer"),
				)
				if route != "" && strings.HasPrefix(route, "/proxy/"+session.UserID+"/") {
					target := route
					if !strings.HasSuffix(target, "/") {
						target += "/"
					}
					target += "?" + r.URL.RawQuery
					http.Redirect(w, r, target, http.StatusFound)
					return
				}
			}
		}
		s.handleRoot(w, r)
	})

	// Wrap with panic recovery
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[goprox] panic: %v\n%s", rec, debug.Stack())
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		mux.ServeHTTP(w, r)
	})
}

// handleBackendLogin detects POST /login from a proxied backend (e.g. Jupyter login form).
// If the user already has a valid session and the Referer or route cookie points to a
// backend service, the request is forwarded there instead of being handled by goprox.
func (s *Server) handleBackendLogin(w http.ResponseWriter, r *http.Request) bool {
	session := auth.GetSessionFromCookies(r.Header.Get("Cookie"), s.sessionSecret)
	if !session.Valid || session.UserID == "" {
		return false
	}

	// Try to find target service from referer or route cookie
	match := s.findBackendService(r, session.UserID)
	if match == nil {
		return false
	}

	// Improved detection: check if this is a GoProx login vs backend login
	ct := r.Header.Get("Content-Type")
	origin := r.Header.Get("Origin")
	referer := r.Header.Get("Referer")

	// GoProx login characteristics:
	// 1. Path is exactly /login (not /proxy/.../login)
	// 2. Origin/Referer doesn't contain /proxy/ path
	// 3. Content-Type is form data
	isGoProxLogin := r.URL.Path == "/login" &&
		strings.Contains(ct, "application/x-www-form-urlencoded") &&
		!strings.Contains(origin, "/proxy/") &&
		!strings.Contains(referer, "/proxy/")

	if isGoProxLogin {
		// Let GoProx handle this login
		return false
	}

	// This appears to be a backend service login form, forward it
	s.forwardAsIs(w, r, match)
	return true
}

// findBackendService tries to locate the target service from Referer or route cookie.
func (s *Server) findBackendService(r *http.Request, username string) *config.ServiceMatch {
	// Referer is the strongest signal for backend-originated login posts.
	referer := r.Header.Get("Referer")
	if referer != "" {
		refPath := "/"
		if u, err := url.Parse(referer); err == nil && u.Path != "" {
			refPath = u.Path
		}
		if match := s.matchRouteForUser(refPath, username); match != nil {
			return match
		}
	}

	route := auth.GetRouteCookieForRequest(r.Header.Get("Cookie"), r.URL.Path, referer)
	if route == "" {
		return nil
	}
	return s.matchRouteForUser(route, username)
}

func (s *Server) matchRouteForUser(route, username string) *config.ServiceMatch {
	match := s.registry.FindService(route)
	if match == nil {
		match = s.registry.FindLegacyService(route, username)
	}
	if match == nil {
		return nil
	}
	pathUser := config.UsernameFromProxyPath(route)
	if pathUser != "" && pathUser != username {
		return nil
	}
	return match
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	session := auth.GetSessionFromCookies(r.Header.Get("Cookie"), s.sessionSecret)

	// Refresh session if needed
	if session.Valid && session.UserID != "" && auth.ShouldRefreshSession(session, s.state.Auth.SessionTTL) {
		secure := auth.IsSecureRequest(r)
		cookie := auth.SetSessionCookie(s.sessionSecret, s.state.Auth.SessionTTL, session.UserID, secure)
		w.Header().Add("Set-Cookie", cookie)
	}

	if session.Valid && session.UserID != "" {
		user := s.registry.GetUser(session.UserID)
		services := []config.ServiceConfig{}
		writable := false
		if user != nil {
			services = user.Config.Services
			writable = config.IsWritable(user.ConfigPath)
		}
		sendHTML(w, 200, web.DashboardPage(session.UserID, services, writable))
	} else {
		sendHTML(w, 200, web.LoginPage(""))
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := auth.ClientIP(r)
	rateKey := ip

	if s.loginLimiter.IsBlocked(rateKey) {
		sendHTML(w, 429, web.LoginPage("登录尝试过多，请 15 分钟后再试"))
		return
	}

	if err := r.ParseForm(); err != nil {
		sendHTML(w, 500, web.LoginPage("登录请求处理失败"))
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	if !config.IsValidUsername(username) || password == "" {
		s.loginLimiter.RecordFailure(rateKey)
		sendHTML(w, 401, web.LoginPage(loginErrorMsg))
		return
	}

	userConfig := s.registry.GetUserConfigForLogin(username)
	if userConfig != nil && auth.VerifyPassword(password, userConfig.Auth.PasswordHash) {
		s.loginLimiter.Reset(rateKey)
		secure := auth.IsSecureRequest(r)
		cookie := auth.SetSessionCookie(s.sessionSecret, s.state.Auth.SessionTTL, username, secure)
		w.Header().Set("Set-Cookie", cookie)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	s.loginLimiter.RecordFailure(rateKey)
	sendHTML(w, 401, web.LoginPage(loginErrorMsg))
}

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	session := auth.GetSessionFromCookies(r.Header.Get("Cookie"), s.sessionSecret)
	if !session.Valid || session.UserID == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// Refresh session if needed
	if auth.ShouldRefreshSession(session, s.state.Auth.SessionTTL) {
		secure := auth.IsSecureRequest(r)
		cookie := auth.SetSessionCookie(s.sessionSecret, s.state.Auth.SessionTTL, session.UserID, secure)
		w.Header().Add("Set-Cookie", cookie)
	}

	path := r.URL.Path

	// Try multi-user path: /proxy/{user}/{service}/...
	multiMatch := s.registry.FindService(path)
	if multiMatch != nil {
		pathUser := config.UsernameFromProxyPath(path)
		if pathUser == "" || pathUser != session.UserID {
			sendHTML(w, 403, web.NotFoundPage())
			return
		}
		s.proxyRequest(w, r, multiMatch)
		return
	}

	// Try legacy path
	legacyMatch := s.registry.FindLegacyService(path, session.UserID)
	if legacyMatch == nil {
		sendHTML(w, 404, web.NotFoundPage())
		return
	}

	s.proxyRequest(w, r, legacyMatch)
}

// proxyRequest forwards a direct /proxy/{user}/{service}/... request, rewriting the path.
func (s *Server) proxyRequest(w http.ResponseWriter, r *http.Request, match *config.ServiceMatch) {
	// Check WebSocket upgrade requests
	if isWebSocketUpgrade(r) && !match.Service.WebSocket {
		http.Error(w, "WebSocket not enabled for this service", http.StatusForbidden)
		return
	}

	forwardCtx := proxy.BuildProxyForwardContext(r, match.Username, match.Service.Path, match.Legacy)
	w.Header().Add("Set-Cookie", auth.SetRouteCookie(forwardCtx.Prefix))
	r.URL.Path = match.RemainingPath
	s.forwardToBackend(w, r, match.Service, forwardCtx)
}

// forwardAsIs forwards a request to the backend keeping the current request path intact.
// Used for referer-based, route-cookie-based, and backend-login routing.
func (s *Server) forwardAsIs(w http.ResponseWriter, r *http.Request, match *config.ServiceMatch) {
	// Check WebSocket upgrade requests
	if isWebSocketUpgrade(r) && !match.Service.WebSocket {
		http.Error(w, "WebSocket not enabled for this service", http.StatusForbidden)
		return
	}

	forwardCtx := proxy.BuildProxyForwardContext(r, match.Username, match.Service.Path, match.Legacy)
	w.Header().Add("Set-Cookie", auth.SetRouteCookie(forwardCtx.Prefix))
	s.forwardToBackend(w, r, match.Service, forwardCtx)
}

func (s *Server) forwardToBackend(w http.ResponseWriter, r *http.Request, svc *config.ServiceConfig, fc proxy.ProxyForwardContext) {
	rp := proxy.NewReverseProxy(svc, fc)
	rp.Transport = &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       90 * time.Second,
	}
	// Add error handler for better debugging
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("[goprox] proxy error: service=%s, path=%s, error=%v", svc.ID, r.URL.Path, err)
		if strings.Contains(err.Error(), "connection refused") {
			http.Error(w, "Service unavailable: backend not responding", http.StatusBadGateway)
		} else if strings.Contains(err.Error(), "timeout") {
			http.Error(w, "Service timeout: backend took too long to respond", http.StatusGatewayTimeout)
		} else {
			http.Error(w, "Proxy error: "+err.Error(), http.StatusBadGateway)
		}
	}
	rp.ServeHTTP(w, r)
}

func (s *Server) handleRefererProxy(w http.ResponseWriter, r *http.Request) bool {
	session := auth.GetSessionFromCookies(r.Header.Get("Cookie"), s.sessionSecret)
	if !session.Valid || session.UserID == "" {
		return false
	}

	// Refresh session if needed
	if auth.ShouldRefreshSession(session, s.state.Auth.SessionTTL) {
		secure := auth.IsSecureRequest(r)
		cookie := auth.SetSessionCookie(s.sessionSecret, s.state.Auth.SessionTTL, session.UserID, secure)
		w.Header().Add("Set-Cookie", cookie)
	}

	referer := r.Header.Get("Referer")
	if referer == "" {
		return false
	}

	// Extract path from referer
	refPath := "/"
	if u, err := url.Parse(referer); err == nil && u.Path != "" {
		refPath = u.Path
	}

	match := s.registry.FindService(refPath)
	if match == nil {
		match = s.registry.FindLegacyService(refPath, session.UserID)
	}
	if match == nil {
		return false
	}

	// Verify user matches
	pathUser := config.UsernameFromProxyPath(refPath)
	if pathUser != "" && pathUser != session.UserID {
		return false
	}

	s.forwardAsIs(w, r, match)
	return true
}

func (s *Server) handleRouteCookieProxy(w http.ResponseWriter, r *http.Request) bool {
	route := auth.GetRouteCookieForRequest(r.Header.Get("Cookie"), r.URL.Path, r.Header.Get("Referer"))
	if route == "" {
		return false
	}

	match := s.registry.FindService(route)
	if match == nil {
		// Try with session user if available
		session := auth.GetSessionFromCookies(r.Header.Get("Cookie"), s.sessionSecret)
		if session.Valid && session.UserID != "" {
			match = s.registry.FindLegacyService(route, session.UserID)
		}
	}
	if match == nil {
		return false
	}

	// If session exists, verify user matches and refresh if needed
	session := auth.GetSessionFromCookies(r.Header.Get("Cookie"), s.sessionSecret)
	if session.Valid && session.UserID != "" {
		// Refresh session if needed
		if auth.ShouldRefreshSession(session, s.state.Auth.SessionTTL) {
			secure := auth.IsSecureRequest(r)
			cookie := auth.SetSessionCookie(s.sessionSecret, s.state.Auth.SessionTTL, session.UserID, secure)
			w.Header().Add("Set-Cookie", cookie)
		}

		pathUser := config.UsernameFromProxyPath(route)
		if pathUser != "" && pathUser != session.UserID {
			return false
		}
	}

	s.forwardAsIs(w, r, match)
	return true
}

func (s *Server) redirectBareService(w http.ResponseWriter, r *http.Request, username string) bool {
	user := s.registry.GetUser(username)
	if user == nil {
		return false
	}

	path := r.URL.Path
	var bestSvc *config.ServiceConfig
	bestLen := -1
	for i := range user.Config.Services {
		svc := &user.Config.Services[i]
		if path == svc.Path || strings.HasPrefix(path, svc.Path+"/") {
			if len(svc.Path) > bestLen {
				bestLen = len(svc.Path)
				bestSvc = svc
			}
		}
	}
	if bestSvc == nil {
		return false
	}

	rest := path[len(bestSvc.Path):]
	query := ""
	if r.URL.RawQuery != "" {
		query = "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, "/proxy/"+username+bestSvc.Path+rest+query, http.StatusFound)
	return true
}

// ScanLoop periodically reloads the user registry.
func (s *Server) ScanLoop(interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.registry.Reload()
			log.Printf("[goprox] scanned %d user(s)", len(s.registry.ListUsers()))
		case <-stop:
			return
		}
	}
}

// UserCount returns the number of loaded users.
func (s *Server) UserCount() int {
	return len(s.registry.ListUsers())
}

func sendHTML(w http.ResponseWriter, status int, html string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	io.WriteString(w, html)
}

// isWebSocketUpgrade checks if the request is a WebSocket upgrade request.
func isWebSocketUpgrade(r *http.Request) bool {
	connection := strings.ToLower(r.Header.Get("Connection"))
	upgrade := strings.ToLower(r.Header.Get("Upgrade"))
	return strings.Contains(connection, "upgrade") && upgrade == "websocket"
}
