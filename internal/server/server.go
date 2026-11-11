package server

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/seqyuan/goprox/internal/api"
	"github.com/seqyuan/goprox/internal/auth"
	"github.com/seqyuan/goprox/internal/config"
	"github.com/seqyuan/goprox/internal/eventlog"
	"github.com/seqyuan/goprox/internal/rate"
	"github.com/seqyuan/goprox/internal/web"
)

const (
	loginErrorMsg     = "用户名或密码错误"
	pendingTTLSeconds = 300 // pending 2FA token lifetime (5 minutes)

	// proxyBodyIdleTimeout is the per-read idle deadline applied while an
	// uploaded/proxied request body is being consumed. The server's absolute
	// ReadTimeout (60s) protects non-proxied form posts, but must not cap a
	// legitimate long upload (Jupyter/RStudio, large files): the deadline is
	// reset to this value before every read instead.
	proxyBodyIdleTimeout = 10 * time.Minute
)

// Server is the main GoProx HTTP server.

type Server struct {
	state         *config.StateConfig
	registry      *config.UserRegistry
	sessionSecret string
	cookieNames   auth.CookieNames
	cookieDomain  string
	publicHost    string
	publicScheme  string
	siteTitle     string
	loginLimiter  *rate.Limiter
	totpLimiter   *rate.Limiter
	apiHandler    *api.Handler
	transport     *http.Transport
	events        *eventlog.Log
}

// New creates a new Server from state config. configDir is where the shared
// user configs live (configDir/users/*.yaml).

func New(state *config.StateConfig, configDir string) *Server {
	// Forwarded headers are only trusted from the configured proxy; with no
	// trusted proxy configured, client IPs and HTTPS detection use the TCP
	// peer directly (X-Forwarded-* is spoofable by any direct client).
	auth.ConfigureTrustedProxy(state.Server.TrustedProxy)

	// Record the gateway's own listen port so backend targets pointing back
	// at it can be rejected as self-loops (write-time and dial-time).
	config.SetGatewayListenPort(state.Server.Port)

	// Restrict kind:"files" roots before the first registry load, so a card
	// pointing outside an administrator-configured allowlist is dropped with a
	// warning at startup instead of serving data.
	config.SetFilesRootAllowlist(state.Server.FilesRoots)

	// The per-user history behind /logs: persisted under <configDir>/logs with a
	// daily rotation, falling back to memory when the directory is unusable.
	events, err := eventlog.NewWithDisk(filepath.Join(configDir, "logs"), eventlog.DefaultPerUser, state.Server.LogRetention())
	if err != nil {
		log.Printf("[goprox] WARNING: 事件日志无法落盘（%v）；本次只保留内存记录（重启清空）", err)
	}

	registry := config.NewUserRegistry(configDir)
	registry.Reload()

	// Site title shown in the top-left corner of the dashboard and login
	// page; falls back to the product name when unset.
	siteTitle := state.Server.Title
	if siteTitle == "" {
		siteTitle = "GoProx"
	}

	srv := &Server{
		state:         state,
		registry:      registry,
		sessionSecret: state.Auth.SessionSecret,
		// Per-instance cookie names (auth.cookie_suffix); default names when the
		// suffix is empty, so single-instance deployments are unaffected.
		cookieNames:  auth.CookieNamesForSuffix(state.Auth.CookieSuffix),
		cookieDomain: state.Server.CookieDomain,
		publicHost:   state.Server.PublicHost,
		publicScheme: state.Server.PublicScheme,
		siteTitle:    siteTitle,
		loginLimiter: rate.NewLimiter(10, 15*time.Minute),
		totpLimiter:  rate.NewLimiter(10, 15*time.Minute),
		apiHandler:   api.NewHandler(registry, state.Auth.SessionSecret, state.Auth.SessionTTL, state.Server.CookieDomain, state.Server.PublicHost, auth.CookieNamesForSuffix(state.Auth.CookieSuffix)),
		// A shared transport lets connection pools be reused across requests
		// instead of creating a fresh one per proxy request. SafeDialContext
		// re-validates backend addresses (and pins the validated IP) at dial
		// time, so the write-time host allowlist cannot be bypassed by a
		// DNS-rebinding / TOCTOU change to the hostname.
		events: events,
		transport: &http.Transport{
			DialContext: config.SafeDialContext,
			// Bounds how long a backend may take to produce its *response
			// headers* — not the body, so SSE/long polling are unaffected. Many
			// frameworks send headers only with the first byte of the answer, so
			// a slow report or a long query would hit the old 30s limit and
			// return 504 while the identical direct request succeeds. 120s keeps
			// a bound on a black-holed backend without cutting off slow work.
			ResponseHeaderTimeout: 120 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
		},
	}
	// The management API records probes into the same per-user history the
	// logs page shows.
	srv.apiHandler.Events = srv.events
	return srv
}

// currentSessionRev returns the per-account session revision derived from the
// user's current password hash. Because the revision is embedded in session
// tokens, changing the password revokes all previously-issued sessions.

func (s *Server) currentSessionRev(username string) string {
	if !config.IsValidUsername(username) {
		return ""
	}
	uc := s.registry.GetUserConfigForLogin(username)
	if uc == nil {
		return ""
	}
	return auth.SessionRev(uc.Auth.PasswordHash)
}

// issueSessionCookie signs a session cookie bound to the user's current
// password-hash revision.

func (s *Server) issueSessionCookie(username string, secure bool) string {
	return s.cookieNames.SetSessionCookieWithDomain(
		s.sessionSecret,
		s.state.Auth.SessionTTL,
		username,
		s.currentSessionRev(username),
		secure,
		s.cookieDomain,
	)
}

// setLoginSessionCookie issues the session cookie and, when a parent Domain is
// configured, expires a pre-vhost host-only cookie with the same name. Without
// this, a browser that upgraded from an older release can send both scopes and
// the server may read the stale one.

func (s *Server) setLoginSessionCookie(w http.ResponseWriter, username string, secure bool) {
	w.Header().Set("Set-Cookie", s.issueSessionCookie(username, secure))
	if s.cookieDomain != "" {
		w.Header().Add("Set-Cookie", s.cookieNames.ClearSessionCookie())
	}
}

// sessionFromCookies validates the session cookie, binding it to the user's
// current password-hash revision.

func (s *Server) sessionFromCookies(cookieHeader string) auth.SessionResult {
	cookies := auth.ParseCookies(cookieHeader)
	token := cookies[s.cookieNames.Session()]
	if token == "" {
		return auth.SessionResult{}
	}
	userID, _, _, err := auth.SessionTokenParts(token)
	if err != nil || userID == "" {
		return auth.SessionResult{}
	}
	return auth.ValidateSessionToken(token, s.sessionSecret, s.currentSessionRev(userID))
}

// Handler returns the HTTP handler for the server.

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// API routes (handled by api.Handler)
	// Use specific exact matches to avoid conflicts with backend service APIs
	mux.HandleFunc("/api/services", func(w http.ResponseWriter, r *http.Request) {
		if s.apiHandler.ServeHTTP(w, r) {
			return
		}
		// Not a gateway API call (e.g. another method): fall back to the usual
		// backend routing just like /api/* does.
		if s.handleRefererProxy(w, r) {
			return
		}
		if s.handleRouteCookieProxy(w, r) {
			return
		}
		if s.handleDefaultServiceProxy(w, r) {
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
		// Not a goprox API: try forwarding to backend service. Referer first:
		// an SPA page's API calls carry the page that issued them, which is a
		// more precise target than the route cookie (most recently visited).
		if s.handleRefererProxy(w, r) {
			return
		}
		if s.handleRouteCookieProxy(w, r) {
			return
		}
		if s.handleDefaultServiceProxy(w, r) {
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
		// Referer first (the issuing page is the precise target), then route
		// cookie, then the user's default service as a last resort.
		if s.handleRefererProxy(w, r) {
			return
		}
		if s.handleRouteCookieProxy(w, r) {
			return
		}
		if s.handleDefaultServiceProxy(w, r) {
			return
		}
		http.NotFound(w, r)
	})

	// Per-user history: a page for humans and a JSON endpoint for scripts.
	mux.HandleFunc("/logs", s.handleLogsPage)
	mux.HandleFunc("/api/logs", s.handleLogsAPI)

	// Favicon
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write([]byte(web.FaviconSVG()))
	})

	// Logout (POST-only; GET renders a confirmation page)
	mux.HandleFunc("/logout", s.handleLogout)

	// Two-factor authentication (second login step)
	mux.HandleFunc("/login/2fa", func(w http.ResponseWriter, r *http.Request) {
		s.handleTwoFA(w, r)
	})

	// TOTP enrollment + management (requires an active session)
	mux.HandleFunc("/2fa/setup", func(w http.ResponseWriter, r *http.Request) {
		s.handleTwoFASetup(w, r)
	})
	mux.HandleFunc("/2fa/qr", func(w http.ResponseWriter, r *http.Request) {
		s.handleTwoFAQr(w, r)
	})
	mux.HandleFunc("/2fa/disable", func(w http.ResponseWriter, r *http.Request) {
		s.handleTwoFADisable(w, r)
	})

	// Login
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			// Login CSRF guard: a cross-site page must not be able to log the
			// victim's browser into the gateway (login CSRF). Browsers send
			// Origin on POST; non-browser clients without Origin pass.
			if !auth.SameOriginRequest(r) {
				sendHTML(w, 403, web.LoginPage(s.siteTitle, "登录请求被拒绝", ""))
				return
			}
			if s.handleBackendLogin(w, r) {
				return
			}
			s.handleLogin(w, r)
			return
		}
		// GET /login: may be a backend service login page (e.g. AnnoVibe redirect).
		// Only forward when a valid session exists; otherwise a stale route
		// cookie would hijack the GoProx login page after logout.
		session := s.sessionFromCookies(r.Header.Get("Cookie"))
		if session.Valid && session.UserID != "" {
			if s.handleRouteCookieProxy(w, r) {
				return
			}
			if s.handleRefererProxy(w, r) {
				return
			}
		}
		s.handleLoginPage(w, r)
	})

	// Proxy routes
	mux.HandleFunc("/proxy/", func(w http.ResponseWriter, r *http.Request) {
		s.handleProxy(w, r)
	})

	// Root route (dashboard/login page)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			// Bare service paths (e.g. /jupyter) must be redirected to the proxied
			// URL before route-cookie forwarding can hijack them and 404.
			session := s.sessionFromCookies(r.Header.Get("Cookie"))
			// An unauthenticated page-like bare path (e.g. a bookmarked SPA route
			// after logout) should show the login page instead of a bare 404.
			// Assets (/x.js) and API paths keep their normal 404 handling.
			if !session.Valid && (r.Method == "GET" || r.Method == "HEAD") && barePathIsPage(r.URL.Path) {
				http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
				return
			}
			if session.Valid && session.UserID != "" && (r.Method == "GET" || r.Method == "HEAD") {
				if s.redirectBareService(w, r, session.UserID) {
					return
				}
			}
			// Other methods cannot be redirected without changing/losing the
			// body, so forward them to the owning service with the service path
			// stripped (e.g. POST /jupyter/api -> backend /api).
			if session.Valid && session.UserID != "" && r.Method != "GET" && r.Method != "HEAD" {
				if s.forwardBareService(w, r, session.UserID) {
					return
				}
			}
			// Opt-in root-absolute routing: an app that emits /docs/... can
			// claim its own bare paths via the current page's Referer (or the
			// route cookie on reload), before default_service page routing.
			if session.Valid && session.UserID != "" {
				if s.handleRootAbsoluteService(w, r, session) {
					return
				}
			}
			// Page-like bare paths go deterministically to the user's default
			// service (root-routed SPAs that cannot understand a /proxy/ prefix);
			// resource-like paths (assets, /api calls) follow the Referer of the
			// page that issued them, then the route cookie, then the default
			// service as a last resort.
			if s.handleDefaultServicePage(w, r) {
				return
			}
			if s.handleRefererProxy(w, r) {
				return
			}
			if s.handleRouteCookieProxy(w, r) {
				return
			}
			if s.handleDefaultServiceProxy(w, r) {
				return
			}
			sendHTML(w, 404, web.NotFoundPage(s.siteTitle))
			return
		}
		// GET / is the GoProx dashboard. Only a clear backend referer may route it.
		// Cookie redirect must run BEFORE handleRefererProxy so the browser
		// address bar is updated to the real proxy URL (not stuck at /?xxx).
		if s.handleProxyEscape(w, r) {
			return
		}
		if s.handleRefererProxy(w, r) {
			return
		}
		s.handleRoot(w, r)
	})

	// Wrap with panic recovery
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				// net/http aborts handlers with ErrAbortHandler when the client
				// disconnects mid-response (httputil.ReverseProxy panics with it
				// on a copy error while streaming, e.g. SSE). The connection is
				// already dead: swallowing the panic is correct, and logging a
				// stack trace or writing an error would only be noise.
				if rec == http.ErrAbortHandler {
					return
				}
				log.Printf("[goprox] panic: %v\n%s", rec, debug.Stack())
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		if s.handleVirtualHost(w, r) {
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// ValidateVHosts checks cross-user hostname uniqueness and the configuration
// required to log in across service subdomains. Call it at startup before
// serving; tests that do not use vhosts can omit it.

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	session := s.sessionFromCookies(r.Header.Get("Cookie"))

	// Refresh session if needed
	if session.Valid && session.UserID != "" && auth.ShouldRefreshSession(session, s.state.Auth.SessionTTL) {
		secure := auth.IsSecureRequest(r)
		cookie := s.issueSessionCookie(session.UserID, secure)
		w.Header().Add("Set-Cookie", cookie)
	}

	if session.Valid && session.UserID != "" {
		user := s.registry.GetUser(session.UserID)
		services := []config.ServiceConfig{}
		writable := false
		twoFAEnabled := false
		if user != nil {
			services = user.Config.Services
			writable = config.IsWritable(user.ConfigPath)
			twoFAEnabled = user.Config.Auth.TOTPSecret != ""
		}
		sendHTML(w, 200, web.DashboardPage(s.siteTitle, session.UserID, services, writable, twoFAEnabled, s.publicSchemeFor(r), s.publicAuthority(r)))
	} else {
		sendHTML(w, 200, web.LoginPage(s.siteTitle, "", ""))
	}
}

func wantsHTML(r *http.Request) bool {
	if strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html") {
		return true
	}
	return strings.EqualFold(r.Header.Get("Sec-Fetch-Dest"), "document")
}

// refererPath returns the Referer's path only when its host matches the
// authority the browser is currently addressing. The path component of an
// external page's URL is attacker-controlled, so it must never be used to
// choose a backend (a cross-site link/Referer could otherwise drive an
// authenticated bare-path request into any proxied service).

func (s *Server) refererPath(r *http.Request) string {
	referer := r.Header.Get("Referer")
	if referer == "" {
		return ""
	}
	u, err := url.Parse(referer)
	if err != nil || u.Path == "" {
		return ""
	}
	if !strings.EqualFold(u.Host, r.Host) {
		return ""
	}
	return u.Path
}

// ScanLoop periodically reloads the user registry.

func (s *Server) ScanLoop(interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			before := len(s.registry.ListUsers())
			s.registry.Reload()
			after := len(s.registry.ListUsers())
			// Only log when the registry actually changed to avoid log spam.
			if after != before {
				log.Printf("[goprox] user registry changed: %d -> %d user(s)", before, after)
			}
		case <-stop:
			return
		}
	}
}

// UserCount returns the number of loaded users.

func (s *Server) UserCount() int {
	return len(s.registry.ListUsers())
}

// ServiceCount returns the number of loaded services across all users.

func (s *Server) ServiceCount() int {
	n := 0
	for _, user := range s.registry.ListUsers() {
		n += len(user.Config.Services)
	}
	return n
}

// FilesServiceCount returns how many loaded cards are kind:"files" (the gateway
// serves those from the local filesystem, so they are the ones server.files_roots
// constrains).

func (s *Server) FilesServiceCount() int {
	n := 0
	for _, user := range s.registry.ListUsers() {
		for _, svc := range user.Config.Services {
			if svc.Kind == config.ServiceKindFiles {
				n++
			}
		}
	}
	return n
}

// HostEntries returns the routable virtual-host index for diagnostics.

func (s *Server) HostEntries() []config.HostEntry {
	return s.registry.HostEntries()
}

// idleReadBody resets the connection's read deadline before each Read so a
// long upload is bounded by idle time between chunks, not by the total request
// duration. SetReadDeadline errors (e.g. HTTP/2 or a test ResponseRecorder)
// are ignored; the original deadline still applies in that case.

type idleReadBody struct {
	io.ReadCloser
	rc      *http.ResponseController
	timeout time.Duration
}

func (b *idleReadBody) Read(p []byte) (int, error) {
	_ = b.rc.SetReadDeadline(time.Now().Add(b.timeout))
	return b.ReadCloser.Read(p)
}

func sendHTML(w http.ResponseWriter, status int, html string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Authenticated pages (and error pages echoing login state) must not be
	// cached by a shared browser/proxy after logout.
	w.Header().Set("Cache-Control", "no-store")
	// Gateway-owned pages must not be framed by unrelated sites (clickjacking
	// of the login/dashboard) or sniffed as a different content type.
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	io.WriteString(w, html)
}

// isWebSocketUpgrade checks if the request is a WebSocket upgrade request.

func isWebSocketUpgrade(r *http.Request) bool {
	connection := strings.ToLower(r.Header.Get("Connection"))
	upgrade := strings.ToLower(r.Header.Get("Upgrade"))
	return strings.Contains(connection, "upgrade") && upgrade == "websocket"
}

// handleLogsPage renders this user's own history (sign-ins, card accesses,
// probes). There is no admin view: an account only ever sees its own events.
func (s *Server) handleLogsPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	session := s.sessionFromCookies(r.Header.Get("Cookie"))
	if !session.Valid || session.UserID == "" {
		http.Redirect(w, r, "/login?next="+url.QueryEscape("/logs"), http.StatusFound)
		return
	}
	if auth.ShouldRefreshSession(session, s.state.Auth.SessionTTL) {
		w.Header().Add("Set-Cookie", s.issueSessionCookie(session.UserID, auth.IsSecureRequest(r)))
	}
	events := s.events.List(session.UserID, eventlog.DefaultPerUser)
	failures := 0
	for _, e := range events {
		if !e.OK {
			failures++
		}
	}
	sendHTML(w, http.StatusOK, web.LogsPage(s.siteTitle, session.UserID, events, failures))
}

// handleLogsAPI returns this user's own history as JSON (newest first).
func (s *Server) handleLogsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	session := s.sessionFromCookies(r.Header.Get("Cookie"))
	if !session.Valid || session.UserID == "" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":"Unauthorized"}`+"\n")
		return
	}
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= eventlog.DefaultPerUser {
			limit = n
		}
	}
	events := s.events.List(session.UserID, limit)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]interface{}{"events": events})
}
