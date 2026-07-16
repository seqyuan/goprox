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

	// API routes (handled by api.Handler); unknown /api/ paths may belong to backend services
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		if s.apiHandler.ServeHTTP(w, r) {
			return
		}
		// Not a goprox API: try forwarding to a backend service (e.g. Next.js SPA)
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
		if r.Method != "POST" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		// If already logged in, forward to backend service (e.g. Jupyter login form)
		if s.handleBackendLogin(w, r) {
			return
		}
		s.handleLogin(w, r)
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
			// Try referer-based routing for subresources
			if s.handleRefererProxy(w, r) {
				return
			}
			// Try route-cookie-based routing
			// Try redirect bare service paths
			session := auth.GetSessionFromCookies(r.Header.Get("Cookie"), s.sessionSecret)
			if session.Valid && session.UserID != "" && r.Method == "GET" {
				if s.redirectBareService(w, r, session.UserID) {
					return
				}
			}
			sendHTML(w, 404, web.NotFoundPage())
			return
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

	// Check if this looks like a backend login (no username field from goprox)
	// Must defer body read until after we know we need it
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return false
	}
	r.Body.Close()

	// Check for username field without consuming the body permanently
	if strings.Contains(string(bodyBytes), "username=") {
		// Restore body for potential goprox login processing
		r.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
		r.ContentLength = int64(len(bodyBytes))
		return false // Let normal login handle it
	}

	// Restore body for backend forwarding
	r.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
	r.ContentLength = int64(len(bodyBytes))

	s.forwardAsIs(w, r, match)
	return true
}

// findBackendService tries to locate the target service from Referer or route cookie.
func (s *Server) findBackendService(r *http.Request, username string) *config.ServiceMatch {
	// Try route cookie first
	cookies := auth.ParseCookies(r.Header.Get("Cookie"))
	if route, ok := cookies[auth.RouteCookieName]; ok && route != "" {
		match := s.registry.FindService(route)
		if match == nil {
			match = s.registry.FindLegacyService(route, username)
		}
		if match != nil {
			pathUser := config.UsernameFromProxyPath(route)
			if pathUser == "" || pathUser == username {
				return match
			}
		}
	}

	// Try Referer
	referer := r.Header.Get("Referer")
	if referer == "" {
		return nil
	}
	refPath := "/"
	if u, err := url.Parse(referer); err == nil && u.Path != "" {
		refPath = u.Path
	}
	match := s.registry.FindService(refPath)
	if match == nil {
		match = s.registry.FindLegacyService(refPath, username)
	}
	if match != nil {
		pathUser := config.UsernameFromProxyPath(refPath)
		if pathUser == "" || pathUser == username {
			return match
		}
	}
	return nil
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	session := auth.GetSessionFromCookies(r.Header.Get("Cookie"), s.sessionSecret)

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
	forwardCtx := proxy.BuildProxyForwardContext(r, match.Username, match.Service.Path, match.Legacy)
	w.Header().Add("Set-Cookie", auth.SetRouteCookie(forwardCtx.Prefix))
	r.URL.Path = match.RemainingPath
	s.forwardToBackend(w, r, match.Service, forwardCtx)
}

// forwardAsIs forwards a request to the backend keeping the current request path intact.
// Used for referer-based, route-cookie-based, and backend-login routing.
func (s *Server) forwardAsIs(w http.ResponseWriter, r *http.Request, match *config.ServiceMatch) {
	forwardCtx := proxy.BuildProxyForwardContext(r, match.Username, match.Service.Path, match.Legacy)
	w.Header().Add("Set-Cookie", auth.SetRouteCookie(forwardCtx.Prefix))
	s.forwardToBackend(w, r, match.Service, forwardCtx)
}

func (s *Server) forwardToBackend(w http.ResponseWriter, r *http.Request, svc *config.ServiceConfig, fc proxy.ProxyForwardContext) {
	rp := proxy.NewReverseProxy(svc, fc)
	rp.Transport = &http.Transport{
		DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       90 * time.Second,
	}
	rp.ServeHTTP(w, r)
}

func (s *Server) handleRefererProxy(w http.ResponseWriter, r *http.Request) bool {
	session := auth.GetSessionFromCookies(r.Header.Get("Cookie"), s.sessionSecret)
	if !session.Valid || session.UserID == "" {
		return false
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
	cookies := auth.ParseCookies(r.Header.Get("Cookie"))
	route, ok := cookies[auth.RouteCookieName]
	if !ok || route == "" {
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

	// If session exists, verify user matches
	session := auth.GetSessionFromCookies(r.Header.Get("Cookie"), s.sessionSecret)
	if session.Valid && session.UserID != "" {
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
