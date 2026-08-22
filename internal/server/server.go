package server

import (
	"io"
	"log"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/seqyuan/goprox/internal/api"
	"github.com/seqyuan/goprox/internal/auth"
	"github.com/seqyuan/goprox/internal/config"
	"github.com/seqyuan/goprox/internal/proxy"
	"github.com/seqyuan/goprox/internal/rate"
	"github.com/seqyuan/goprox/internal/web"
)

const (
	loginErrorMsg     = "用户名或密码错误"
	pendingTTLSeconds = 300 // pending 2FA token lifetime (5 minutes)
)

// Server is the main GoProx HTTP server.
type Server struct {
	state         *config.StateConfig
	registry      *config.UserRegistry
	sessionSecret string
	siteTitle     string
	loginLimiter  *rate.Limiter
	totpLimiter   *rate.Limiter
	apiHandler    *api.Handler
	transport     *http.Transport
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

	registry := config.NewUserRegistry(configDir)
	registry.Reload()

	// Site title shown in the top-left corner of the dashboard and login
	// page; falls back to the product name when unset.
	siteTitle := state.Server.Title
	if siteTitle == "" {
		siteTitle = "GoProx"
	}

	return &Server{
		state:         state,
		registry:      registry,
		sessionSecret: state.Auth.SessionSecret,
		siteTitle:     siteTitle,
		loginLimiter:  rate.NewLimiter(10, 15*time.Minute),
		totpLimiter:   rate.NewLimiter(10, 15*time.Minute),
		apiHandler:    api.NewHandler(registry, state.Auth.SessionSecret),
		// A shared transport lets connection pools be reused across requests
		// instead of creating a fresh one per proxy request. SafeDialContext
		// re-validates backend addresses (and pins the validated IP) at dial
		// time, so the write-time host allowlist cannot be bypassed by a
		// DNS-rebinding / TOCTOU change to the hostname.
		transport: &http.Transport{
			DialContext:           config.SafeDialContext,
			ResponseHeaderTimeout: 30 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
		},
	}
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
	return auth.SetSessionCookie(s.sessionSecret, s.state.Auth.SessionTTL, username, s.currentSessionRev(username), secure)
}

// sessionFromCookies validates the session cookie, binding it to the user's
// current password-hash revision.
func (s *Server) sessionFromCookies(cookieHeader string) auth.SessionResult {
	cookies := auth.ParseCookies(cookieHeader)
	token := cookies[auth.SessionCookieName]
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

	// Favicon
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write([]byte(web.FaviconSVG()))
	})

	// Logout
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", auth.ClearSessionCookie())
		// Route cookies outlive the session and would keep forwarding bare
		// paths to backends after logout; clear every one the browser holds.
		for _, c := range auth.ClearRouteCookies(r.Header.Get("Cookie")) {
			w.Header().Add("Set-Cookie", c)
		}
		http.Redirect(w, r, "/", http.StatusFound)
	})

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
			if session.Valid && session.UserID != "" && r.Method == "GET" {
				if s.redirectBareService(w, r, session.UserID) {
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
		mux.ServeHTTP(w, r)
	})
}

// handleBackendLogin detects POST /login from a proxied backend (e.g. Jupyter login form).
// If the user already has a valid session and the Referer or route cookie points to a
// backend service, the request is forwarded there instead of being handled by goprox.
func (s *Server) handleBackendLogin(w http.ResponseWriter, r *http.Request) bool {
	session := s.sessionFromCookies(r.Header.Get("Cookie"))
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

func (s *Server) handleProxyEscape(w http.ResponseWriter, r *http.Request) bool {
	// When a user lands on /?xxx (e.g. /?refresh=1) after escaping the proxy
	// prefix, redirect them back to the correct proxy URL via the route cookie.
	if r.URL.RawQuery == "" {
		return false
	}
	session := s.sessionFromCookies(r.Header.Get("Cookie"))
	if !session.Valid || session.UserID == "" {
		return false
	}
	route := auth.GetRouteCookieForRequest(
		r.Header.Get("Cookie"), "", r.Header.Get("Referer"),
	)
	if route == "" || !strings.HasPrefix(route, "/proxy/"+session.UserID+"/") {
		return false
	}
	target := route
	if !strings.HasSuffix(target, "/") {
		target += "/"
	}
	target += "?" + r.URL.RawQuery
	http.Redirect(w, r, target, http.StatusFound)
	return true
}

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
		sendHTML(w, 200, web.DashboardPage(s.siteTitle, session.UserID, services, writable, twoFAEnabled))
	} else {
		sendHTML(w, 200, web.LoginPage(s.siteTitle, "", ""))
	}
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	if !validLoginNext(next) {
		next = ""
	}
	sendHTML(w, 200, web.LoginPage(s.siteTitle, "", next))
}

// validLoginNext restricts post-login redirects to in-site proxy URLs,
// preventing open-redirect abuse.
func validLoginNext(next string) bool {
	return strings.HasPrefix(next, "/proxy/") && !strings.HasPrefix(next, "//")
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Parse the form before rate limiting: the limit key combines the client
	// IP with the submitted username so a shared-NAT office/lab does not lock
	// out everyone on one user's typos, and an attacker cannot freeze a whole
	// subnet by flooding failures.
	if err := r.ParseForm(); err != nil {
		sendHTML(w, 500, web.LoginPage(s.siteTitle, "登录请求处理失败", ""))
		return
	}

	ip := auth.ClientIP(r)
	username := strings.TrimSpace(r.FormValue("username"))
	// Username matching is case-sensitive, but rate limiting deliberately is
	// not, so "Alice" and "alice" share a failure budget.
	rateKey := ip + "|" + strings.ToLower(username)

	if s.loginLimiter.IsBlocked(rateKey) {
		sendHTML(w, 429, web.LoginPage(s.siteTitle, "登录尝试过多，请 15 分钟后再试", ""))
		return
	}

	password := r.FormValue("password")
	next := r.FormValue("next")
	if !validLoginNext(next) {
		next = ""
	}

	if !config.IsValidUsername(username) || password == "" {
		s.loginLimiter.RecordFailure(rateKey)
		sendHTML(w, 401, web.LoginPage(s.siteTitle, loginErrorMsg, next))
		return
	}

	userConfig := s.registry.GetUserConfigForLogin(username)
	passwordHash := ""
	if userConfig != nil {
		passwordHash = userConfig.Auth.PasswordHash
	}
	// Timing-safe verify: even for unknown usernames a bcrypt comparison runs,
	// so login latency cannot be used to enumerate valid accounts.
	if auth.VerifyPasswordTimingSafe(password, passwordHash) {
		s.loginLimiter.Reset(rateKey)
		secure := auth.IsSecureRequest(r)
		if next == "" {
			next = "/"
		}
		// Account has TOTP enabled: hold at the second factor before issuing
		// a real session.
		if userConfig != nil && userConfig.Auth.TOTPSecret != "" {
			w.Header().Set("Set-Cookie", auth.SetPendingCookie(s.sessionSecret, pendingTTLSeconds, username, secure))
			http.Redirect(w, r, "/login/2fa?next="+url.QueryEscape(next), http.StatusFound)
			return
		}
		cookie := s.issueSessionCookie(username, secure)
		w.Header().Set("Set-Cookie", cookie)
		http.Redirect(w, r, next, http.StatusFound)
		return
	}

	s.loginLimiter.RecordFailure(rateKey)
	sendHTML(w, 401, web.LoginPage(s.siteTitle, loginErrorMsg, next))
}

// ---- two-factor authentication (TOTP) ----

// handleTwoFA serves the second login step: GET renders the code form (only
// when a valid pending token exists); POST verifies the code.
func (s *Server) handleTwoFA(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		if !auth.SameOriginRequest(r) {
			sendHTML(w, 403, web.TwoFAPage(s.siteTitle, "请求被拒绝", ""))
			return
		}
		s.handleTwoFAPost(w, r)
		return
	}

	cookies := auth.ParseCookies(r.Header.Get("Cookie"))
	userID, ok := auth.ValidatePendingToken(cookies[auth.TOTACookieName], s.sessionSecret)
	if !ok || userID == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	next := r.URL.Query().Get("next")
	if !validLoginNext(next) {
		next = ""
	}
	sendHTML(w, 200, web.TwoFAPage(s.siteTitle, "", next))
}

func (s *Server) handleTwoFAPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		sendHTML(w, 500, web.TwoFAPage(s.siteTitle, "请求处理失败", ""))
		return
	}

	cookies := auth.ParseCookies(r.Header.Get("Cookie"))
	userID, ok := auth.ValidatePendingToken(cookies[auth.TOTACookieName], s.sessionSecret)
	if !ok || userID == "" {
		// Pending token missing/expired: back to the password step.
		next := r.FormValue("next")
		http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusFound)
		return
	}

	ip := auth.ClientIP(r)
	rateKey := ip + "|2fa|" + strings.ToLower(userID)
	if s.totpLimiter.IsBlocked(rateKey) {
		sendHTML(w, 429, web.TwoFAPage(s.siteTitle, "验证尝试过多，请 15 分钟后再试", r.FormValue("next")))
		return
	}

	uc := s.registry.GetUserConfigForLogin(userID)
	if uc == nil || uc.Auth.TOTPSecret == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	code := strings.TrimSpace(r.FormValue("code"))
	if !auth.VerifyTOTP(uc.Auth.TOTPSecret, code, time.Now()) {
		s.totpLimiter.RecordFailure(rateKey)
		sendHTML(w, 401, web.TwoFAPage(s.siteTitle, "动态码错误或已过期", r.FormValue("next")))
		return
	}

	s.totpLimiter.Reset(rateKey)
	secure := auth.IsSecureRequest(r)
	w.Header().Set("Set-Cookie", s.issueSessionCookie(userID, secure))
	w.Header().Add("Set-Cookie", auth.ClearPendingCookie())
	next := r.FormValue("next")
	if !validLoginNext(next) {
		next = "/"
	}
	http.Redirect(w, r, next, http.StatusFound)
}

// handleTwoFASetup enrolls (or rotates) TOTP for the logged-in user.
func (s *Server) handleTwoFASetup(w http.ResponseWriter, r *http.Request) {
	session := s.sessionFromCookies(r.Header.Get("Cookie"))
	if !session.Valid || session.UserID == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.Method == "POST" {
		if !auth.SameOriginRequest(r) {
			sendHTML(w, 403, web.TwoFASetupPage(s.siteTitle, "请求被拒绝", "", s.twoFAEnabled(session.UserID)))
			return
		}
		s.handleTwoFASetupPost(w, r, session.UserID)
		return
	}

	enabled := s.twoFAEnabled(session.UserID)
	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		sendHTML(w, 500, web.TwoFASetupPage(s.siteTitle, "生成密钥失败", "", enabled))
		return
	}
	secure := auth.IsSecureRequest(r)
	w.Header().Set("Set-Cookie", auth.SetSetupCookie(secret, s.sessionSecret, pendingTTLSeconds, secure))
	sendHTML(w, 200, web.TwoFASetupPage(s.siteTitle, "", secret, enabled))
}

func (s *Server) handleTwoFASetupPost(w http.ResponseWriter, r *http.Request, username string) {
	enabled := s.twoFAEnabled(username)
	if err := r.ParseForm(); err != nil {
		sendHTML(w, 500, web.TwoFASetupPage(s.siteTitle, "请求处理失败", "", enabled))
		return
	}

	cookies := auth.ParseCookies(r.Header.Get("Cookie"))
	secret, ok := auth.ValidateSetupToken(cookies[auth.TOTASetupCookie], s.sessionSecret)
	if !ok {
		sendHTML(w, 401, web.TwoFASetupPage(s.siteTitle, "设置会话已过期，请重新开始", "", enabled))
		return
	}

	code := strings.TrimSpace(r.FormValue("code"))
	if !auth.VerifyTOTP(secret, code, time.Now()) {
		sendHTML(w, 401, web.TwoFASetupPage(s.siteTitle, "动态码错误或已过期，请重试", secret, enabled))
		return
	}

	user := s.registry.GetUser(username)
	if user == nil {
		sendHTML(w, 404, web.NotFoundPage(s.siteTitle))
		return
	}
	if err := config.UpdateTOTPSecret(user.ConfigPath, secret); err != nil {
		sendHTML(w, 500, web.TwoFASetupPage(s.siteTitle, "保存失败：配置文件不可写", secret, enabled))
		return
	}
	s.registry.Reload()
	w.Header().Add("Set-Cookie", auth.ClearSetupCookie())
	http.Redirect(w, r, "/", http.StatusFound)
}

// twoFAEnabled reports whether the user has a TOTP secret configured.
func (s *Server) twoFAEnabled(username string) bool {
	user := s.registry.GetUser(username)
	return user != nil && user.Config.Auth.TOTPSecret != ""
}

// handleTwoFAQr renders the provisioning QR code for the pending setup secret.
func (s *Server) handleTwoFAQr(w http.ResponseWriter, r *http.Request) {
	session := s.sessionFromCookies(r.Header.Get("Cookie"))
	if !session.Valid || session.UserID == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	cookies := auth.ParseCookies(r.Header.Get("Cookie"))
	secret, ok := auth.ValidateSetupToken(cookies[auth.TOTASetupCookie], s.sessionSecret)
	if !ok {
		http.Error(w, "invalid setup", http.StatusBadRequest)
		return
	}
	png, err := qrcode.Encode(auth.TOTPURI(session.UserID, secret), qrcode.Medium, 256)
	if err != nil {
		http.Error(w, "qr error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Write(png)
}

// handleTwoFADisable turns off TOTP for the logged-in user.
func (s *Server) handleTwoFADisable(w http.ResponseWriter, r *http.Request) {
	session := s.sessionFromCookies(r.Header.Get("Cookie"))
	if !session.Valid || session.UserID == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if r.Method != "POST" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if !auth.SameOriginRequest(r) {
		sendHTML(w, 403, web.NotFoundPage(s.siteTitle))
		return
	}

	user := s.registry.GetUser(session.UserID)
	if user == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if err := config.UpdateTOTPSecret(user.ConfigPath, ""); err != nil {
		sendHTML(w, 500, web.LoginPage(s.siteTitle, "关闭失败：配置文件不可写", ""))
		return
	}
	s.registry.Reload()
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	session := s.sessionFromCookies(r.Header.Get("Cookie"))
	if !session.Valid || session.UserID == "" {
		// Send the unauthenticated user to the login page and remember where
		// they were headed so they land back on their service after login.
		next := r.URL.RequestURI()
		http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusFound)
		return
	}

	// Refresh session if needed
	if auth.ShouldRefreshSession(session, s.state.Auth.SessionTTL) {
		secure := auth.IsSecureRequest(r)
		cookie := s.issueSessionCookie(session.UserID, secure)
		w.Header().Add("Set-Cookie", cookie)
	}

	path := r.URL.Path

	// Try multi-user path: /proxy/{user}/{service}/...
	multiMatch := s.registry.FindService(path)
	if multiMatch != nil {
		pathUser := config.UsernameFromProxyPath(path)
		if pathUser == "" || pathUser != session.UserID {
			sendHTML(w, 403, web.NotFoundPage(s.siteTitle))
			return
		}
		s.proxyRequest(w, r, multiMatch)
		return
	}

	// Try legacy path
	legacyMatch := s.registry.FindLegacyService(path, session.UserID)
	if legacyMatch == nil {
		sendHTML(w, 404, web.NotFoundPage(s.siteTitle))
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
	forwardCtx.SSO = s.state.SSO
	// The injected <base> must point at the directory of the actual document
	// (e.g. /proxy/user/svc/report/page.html -> /proxy/user/svc/report/), not
	// the service prefix, so relative links in plain HTML files in
	// subdirectories resolve correctly.
	forwardCtx.Base = proxy.BaseForPath(forwardCtx.Prefix, match.RemainingPath)
	for _, c := range auth.SetRouteCookies(forwardCtx.Prefix) {
		w.Header().Add("Set-Cookie", c)
	}
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
	forwardCtx.SSO = s.state.SSO
	for _, c := range auth.SetRouteCookies(forwardCtx.Prefix) {
		w.Header().Add("Set-Cookie", c)
	}
	s.forwardToBackend(w, r, match.Service, forwardCtx)
}

func (s *Server) forwardToBackend(w http.ResponseWriter, r *http.Request, svc *config.ServiceConfig, fc proxy.ProxyForwardContext) {
	rp := proxy.NewReverseProxy(svc, fc)
	rp.Transport = s.transport
	// Go's ReverseProxy logs body-copy errors ("unexpected EOF") through its
	// internal logger whenever the client disconnects mid-stream (SSE tab
	// close, navigation). Those are expected, not outages, and meaningful
	// failures are already logged by ErrorHandler below, so silence the
	// standard-library noise.
	rp.ErrorLog = log.New(io.Discard, "", 0)
	// Add error handler: log the full error server-side, reply generically so
	// backend host/port details are not leaked to clients.
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		// The client went away (tab closed / navigation during a stream); the
		// connection is dead, so there is nothing to write and the "context
		// canceled" error is expected, not an outage.
		if r.Context().Err() != nil {
			return
		}
		log.Printf("[goprox] proxy error: service=%s, path=%s, error=%v", svc.ID, r.URL.Path, err)
		switch {
		case strings.Contains(err.Error(), "connection refused"):
			http.Error(w, "Service unavailable: backend not responding", http.StatusBadGateway)
		case strings.Contains(err.Error(), "timeout"):
			http.Error(w, "Service timeout: backend took too long to respond", http.StatusGatewayTimeout)
		default:
			http.Error(w, "Proxy error", http.StatusBadGateway)
		}
	}
	rp.ServeHTTP(w, r)
}

func (s *Server) handleRefererProxy(w http.ResponseWriter, r *http.Request) bool {
	session := s.sessionFromCookies(r.Header.Get("Cookie"))
	if !session.Valid || session.UserID == "" {
		return false
	}

	// Refresh session if needed
	if auth.ShouldRefreshSession(session, s.state.Auth.SessionTTL) {
		secure := auth.IsSecureRequest(r)
		cookie := s.issueSessionCookie(session.UserID, secure)
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

	// Route cookies are context hints, not credentials: without a valid
	// session they must never grant backend access (the session may have
	// expired or the user may have logged out).
	session := s.sessionFromCookies(r.Header.Get("Cookie"))
	if !session.Valid || session.UserID == "" {
		next := r.URL.RequestURI()
		http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusFound)
		return true
	}

	// Refresh session if needed
	if auth.ShouldRefreshSession(session, s.state.Auth.SessionTTL) {
		secure := auth.IsSecureRequest(r)
		cookie := s.issueSessionCookie(session.UserID, secure)
		w.Header().Add("Set-Cookie", cookie)
	}

	match := s.registry.FindService(route)
	if match == nil {
		match = s.registry.FindLegacyService(route, session.UserID)
	}
	if match == nil {
		return false
	}

	pathUser := config.UsernameFromProxyPath(route)
	if pathUser != "" && pathUser != session.UserID {
		return false
	}

	s.forwardAsIs(w, r, match)
	return true
}

// handleDefaultServiceProxy forwards unclaimed bare gateway paths to the
// user's configured default service (DefaultService), so root-routed SPAs
// (Nuxt / Next / Vite client routers, which match window.location.pathname
// against root routes and cannot understand a /proxy/<user>/ prefix) work at
// the gateway root with zero app-side basePath/baseURL changes. It runs only
// after route-cookie and Referer forwarding have failed; forwardAsIs stamps
// the route cookies that keep subsequent sub-resource requests on the same
// service. Without a valid session the request falls through to the 404.
func (s *Server) handleDefaultServiceProxy(w http.ResponseWriter, r *http.Request) bool {
	return s.forwardToDefaultService(w, r)
}

// handleDefaultServicePage deterministically routes page-like bare paths
// (SPA views like /dashboard, not assets or API calls) to the user's default
// service, before Referer / route-cookie forwarding. This makes root-based
// SPA navigation stable regardless of which other services were visited most
// recently; resource-like paths are left to the Referer/route-cookie chain so
// they stick to the page that issued them.
func (s *Server) handleDefaultServicePage(w http.ResponseWriter, r *http.Request) bool {
	if !barePathIsPage(r.URL.Path) {
		return false
	}
	return s.forwardToDefaultService(w, r)
}

func (s *Server) forwardToDefaultService(w http.ResponseWriter, r *http.Request) bool {
	session := s.sessionFromCookies(r.Header.Get("Cookie"))
	if !session.Valid || session.UserID == "" {
		return false
	}
	user := s.registry.GetUser(session.UserID)
	if user == nil || user.Config.DefaultService == "" {
		return false
	}
	svc := config.ServiceByID(user.Config.Services, user.Config.DefaultService)
	if svc == nil {
		return false
	}
	match := &config.ServiceMatch{
		Username:      session.UserID,
		Service:       svc,
		RemainingPath: r.URL.Path,
	}
	s.forwardAsIs(w, r, match)
	return true
}

// barePathIsPage reports whether an unclaimed bare gateway path looks like a
// page navigation (a client-routed SPA view) rather than a static asset or
// API call. Page-like paths are routed to the user's default service
// deterministically; resource-like paths (segments with file extensions, or
// paths under known asset/API roots) fall back to Referer / route-cookie
// forwarding so they follow the page that requested them.
func barePathIsPage(p string) bool {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	lower := strings.ToLower(p)
	for _, seg := range strings.Split(lower, "/") {
		if i := strings.LastIndexByte(seg, '.'); i > 0 && i < len(seg)-1 {
			return false
		}
	}
	for _, root := range []string{
		"/api/", "/plugins/", "/_nuxt/", "/_next/", "/assets/", "/static/",
		"/vendors/", "/files/", "/favicon.", "/manifest.webmanifest",
	} {
		if strings.HasPrefix(lower, root) {
			return false
		}
	}
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

func sendHTML(w http.ResponseWriter, status int, html string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
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
