package server

// 登录、登出与两步验证（TOTP）的 HTTP 处理器。

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/seqyuan/goprox/internal/auth"
	"github.com/seqyuan/goprox/internal/config"
	"github.com/seqyuan/goprox/internal/web"
)

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	// A session cannot be stored on an authority outside cookie_domain (the
	// session cookie carries a parent Domain), so a login attempt there would
	// silently bounce back to this page. Say so instead of showing a form that
	// cannot work.
	if msg := s.loginHostMismatch(r); msg != "" {
		sendHTML(w, 200, web.LoginPage(s.siteTitle, msg, ""))
		return
	}
	next := r.URL.Query().Get("next")
	// Pre-auth we only require that an absolute target is one of the
	// configured service hosts; the post-auth check narrows it to the user.
	if !s.validLoginNext(r, next, "") {
		next = ""
	}
	sendHTML(w, 200, web.LoginPage(s.siteTitle, "", next))
}

// loginHostMismatch reports why no session can be established on the authority
// this request addressed, or "" when login is possible here.
//
// With server.cookie_domain set (required for virtual hosts), every session
// cookie is issued with a parent Domain. A browser on a host outside that
// domain (an IP address, a short hostname, another zone) refuses to store it,
// so the login "succeeds" and the very next request lands back on the login
// page with no error anywhere. That silent loop is the single most confusing
// vhost misconfiguration, so it is refused explicitly.
func (s *Server) loginHostMismatch(r *http.Request) string {
	if s.cookieDomain == "" {
		return ""
	}
	host := config.HostFromHostPort(r.Host)
	if host == "" || config.HostWithinCookieDomain(host, s.cookieDomain) {
		return ""
	}
	example := s.publicAuthority(r)
	if example == "" {
		example = strings.TrimPrefix(s.cookieDomain, ".")
	}
	return fmt.Sprintf("当前访问地址 %s 不在网关的会话 Cookie 域 %s 内：浏览器不会保存会话 Cookie，登录后会立刻回到登录页。请改用该域内的地址访问，例如 %s",
		host, s.cookieDomain, example)
}

// validLoginNext restricts post-login redirects to in-site proxy URLs or a
// service hostname, preventing open-redirect abuse. With username == "" it
// only checks that an absolute target is a configured vhost; with a username
// it also requires that the vhost belongs to that user.

func (s *Server) validLoginNext(r *http.Request, next, username string) bool {
	if next == "" {
		return false
	}
	if len(next) > 4096 || strings.ContainsAny(next, "\r\n") {
		return false
	}
	if strings.HasPrefix(next, "/proxy/") && !strings.HasPrefix(next, "//") {
		return true
	}
	u, err := url.Parse(next)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return false
	}
	if u.Scheme != s.publicSchemeFor(r) {
		return false
	}
	target := s.registry.FindByHost(config.HostFromHostPort(u.Host))
	if target == nil {
		return false
	}
	if username != "" && target.Username != username {
		return false
	}
	// Do not allow the login redirect to switch ports. The public authority
	// is authoritative: when it has a non-default port, next must carry it;
	// when it has no port, next may only use the scheme's default port.
	expectedPort := ""
	if _, p, err := net.SplitHostPort(s.publicAuthority(r)); err == nil {
		expectedPort = p
	}
	nextPort := u.Port()
	if expectedPort != "" {
		if nextPort == "" {
			if !((u.Scheme == "http" && expectedPort == "80") || (u.Scheme == "https" && expectedPort == "443")) {
				return false
			}
		} else if nextPort != expectedPort {
			return false
		}
	} else if nextPort != "" {
		if !((u.Scheme == "http" && nextPort == "80") || (u.Scheme == "https" && nextPort == "443")) {
			return false
		}
	}
	return true
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Refuse a login the browser could never keep: see loginHostMismatch. This
	// runs before the password step so no session cookie (and no 2FA pending
	// cookie) is issued for an authority outside cookie_domain.
	if msg := s.loginHostMismatch(r); msg != "" {
		sendHTML(w, http.StatusBadRequest, web.LoginPage(s.siteTitle, msg, ""))
		return
	}
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
		s.recordLogin(username, false, "登录尝试过多，已被限流")
		sendHTML(w, 429, web.LoginPage(s.siteTitle, "登录尝试过多，请 15 分钟后再试", ""))
		return
	}

	password := r.FormValue("password")
	next := r.FormValue("next")
	// Drop malformed input before reflecting it back on a failed login; the
	// post-auth check below narrows a valid vhost target to this user.
	if !s.validLoginNext(r, next, "") {
		next = ""
	}

	if !config.IsValidUsername(username) || password == "" {
		s.loginLimiter.RecordFailure(rateKey)
		s.recordLogin(username, false, "用户名或密码为空/不合法")
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
		if !s.validLoginNext(r, next, username) {
			next = "/"
		}
		// Migrate a pre-bcrypt hash now that we have the plaintext: the account
		// stays usable and the weak hash disappears on the next login. The
		// session revision is derived from the hash, so every token issued
		// below must use the upgraded one.
		passwordHash = s.upgradePasswordHash(username, password, passwordHash)
		if userConfig == nil || userConfig.Auth.TOTPSecret == "" {
			s.recordLogin(username, true, "密码登录")
		}
		// Account has TOTP enabled: hold at the second factor before issuing
		// a real session.
		if userConfig != nil && userConfig.Auth.TOTPSecret != "" {
			rev := auth.SessionRev(passwordHash)
			w.Header().Set("Set-Cookie", s.cookieNames.SetPendingCookie(s.sessionSecret, pendingTTLSeconds, username, rev, secure))
			http.Redirect(w, r, "/login/2fa?next="+url.QueryEscape(next), http.StatusFound)
			return
		}
		s.setLoginSessionCookie(w, username, secure)
		http.Redirect(w, r, next, http.StatusFound)
		return
	}

	s.loginLimiter.RecordFailure(rateKey)
	s.recordLogin(username, false, loginErrorMsg)
	sendHTML(w, 401, web.LoginPage(s.siteTitle, loginErrorMsg, next))
}

// upgradePasswordHash rewrites a legacy (pre-bcrypt) password hash after a
// successful login, so existing accounts migrate without a forced reset. It
// returns the hash that is now authoritative: the upgraded one on success, or
// the original when the write fails (read-only config) or the hash was already
// bcrypt.

func (s *Server) upgradePasswordHash(username, password, current string) string {
	if !auth.IsLegacyHash(current) {
		return current
	}
	user := s.registry.GetUser(username)
	if user == nil {
		return current
	}
	upgraded := auth.HashPassword(password)
	if err := config.UpdatePasswordHash(user.ConfigPath, upgraded); err != nil {
		// Keep the session flow working: verification already succeeded, so a
		// read-only config must not block the login.
		log.Printf("[goprox] password hash upgrade for %s failed: %v", username, err)
		return current
	}
	log.Printf("[goprox] password hash for %s upgraded to bcrypt", username)
	// Reload so the session-revision cache (mtime/size keyed) sees the new hash
	// before any cookie is issued.
	s.registry.Reload()
	return upgraded
}

// ---- two-factor authentication (TOTP) ----

// handleTwoFA serves the second login step: GET renders the code form (only
// when a valid pending token exists); POST verifies the code.

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		// Never change state on GET: a cross-site link/image must not be able
		// to log the user out. Show a confirmation form instead.
		sendHTML(w, http.StatusOK, web.LogoutConfirmPage(s.siteTitle))
		return
	case http.MethodPost:
		if !auth.SameOriginRequest(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Set-Cookie", s.cookieNames.ClearSessionCookieWithDomain(s.cookieDomain))
	// A pre-vhost (or pre-cookie-domain) host-only session cookie can coexist
	// with the parent-domain one. Clearing only the Domain variant leaves that
	// host-only cookie valid, so logout would not actually log the user out.
	if s.cookieDomain != "" {
		w.Header().Add("Set-Cookie", s.cookieNames.ClearSessionCookie())
	}
	// Temporary 2FA state must not survive logout (the setup cookie also
	// carries a plaintext pending TOTP secret).
	w.Header().Add("Set-Cookie", s.cookieNames.ClearPendingCookie())
	w.Header().Add("Set-Cookie", s.cookieNames.ClearSetupCookie())
	// Route cookies outlive the session and would keep forwarding bare paths to
	// backends after logout; clear every one the browser holds.
	for _, c := range s.cookieNames.ClearRouteCookies(r.Header.Get("Cookie")) {
		w.Header().Add("Set-Cookie", c)
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) handleTwoFA(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		if !auth.SameOriginRequest(r) {
			sendHTML(w, 403, web.TwoFAPage(s.siteTitle, "请求被拒绝", ""))
			return
		}
		s.handleTwoFAPost(w, r)
		return
	}

	userID, ok := s.pendingTwoFAUser(r.Header.Get("Cookie"))
	if !ok || userID == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	next := r.URL.Query().Get("next")
	if !s.validLoginNext(r, next, userID) {
		next = ""
	}
	sendHTML(w, 200, web.TwoFAPage(s.siteTitle, "", next))
}

// pendingTwoFAUser validates the pending-2FA cookie against the account's
// current password revision. A password reset therefore invalidates an
// in-flight password step, not only already-issued sessions.

func (s *Server) pendingTwoFAUser(cookieHeader string) (string, bool) {
	token := auth.ParseCookies(cookieHeader)[s.cookieNames.TOTAPending()]
	if token == "" {
		return "", false
	}
	userID, err := auth.PendingTokenUser(token)
	if err != nil || !config.IsValidUsername(userID) {
		return "", false
	}
	return auth.ValidatePendingToken(token, s.sessionSecret, s.currentSessionRev(userID))
}

func (s *Server) handleTwoFAPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		sendHTML(w, 500, web.TwoFAPage(s.siteTitle, "请求处理失败", ""))
		return
	}

	userID, ok := s.pendingTwoFAUser(r.Header.Get("Cookie"))
	if !ok || userID == "" {
		// Pending token missing/expired: back to the password step.
		next := r.FormValue("next")
		http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusFound)
		return
	}
	next := r.FormValue("next")
	if !s.validLoginNext(r, next, userID) {
		next = ""
	}

	ip := auth.ClientIP(r)
	rateKey := ip + "|2fa|" + strings.ToLower(userID)
	if s.totpLimiter.IsBlocked(rateKey) {
		s.recordLogin(userID, false, "两步验证尝试过多，已被限流")
		sendHTML(w, 429, web.TwoFAPage(s.siteTitle, "验证尝试过多，请 15 分钟后再试", next))
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
		s.recordLogin(userID, false, "动态码错误或已过期")
		sendHTML(w, 401, web.TwoFAPage(s.siteTitle, "动态码错误或已过期", next))
		return
	}

	s.totpLimiter.Reset(rateKey)
	s.recordLogin(userID, true, "密码 + 两步验证登录")
	secure := auth.IsSecureRequest(r)
	s.setLoginSessionCookie(w, userID, secure)
	w.Header().Add("Set-Cookie", s.cookieNames.ClearPendingCookie())
	if next == "" {
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
	// Reuse the secret already in flight for this user: a refresh, a second tab
	// or a browser back-navigation must not invalidate the QR code the user is
	// currently scanning — that surfaced as "动态码错误或已过期" on a correct
	// code. Only a missing/expired/foreign cookie mints a fresh secret.
	secret := s.pendingSetupSecret(r, session.UserID)
	if secret == "" {
		var err error
		secret, err = auth.GenerateTOTPSecret()
		if err != nil {
			sendHTML(w, 500, web.TwoFASetupPage(s.siteTitle, "生成密钥失败", "", enabled))
			return
		}
	}
	secure := auth.IsSecureRequest(r)
	w.Header().Set("Set-Cookie", s.cookieNames.SetSetupCookie(session.UserID, secret, s.sessionSecret, pendingTTLSeconds, secure))
	sendHTML(w, 200, web.TwoFASetupPage(s.siteTitle, "", secret, enabled))
}

// pendingSetupSecret returns the not-yet-saved TOTP secret carried by this
// user's setup cookie, or "" when there is none to reuse.
func (s *Server) pendingSetupSecret(r *http.Request, username string) string {
	cookies := auth.ParseCookies(r.Header.Get("Cookie"))
	setupUser, secret, ok := auth.ValidateSetupToken(cookies[s.cookieNames.TOTASetup()], s.sessionSecret)
	if !ok || setupUser != username {
		return ""
	}
	return secret
}

func (s *Server) handleTwoFASetupPost(w http.ResponseWriter, r *http.Request, username string) {
	enabled := s.twoFAEnabled(username)
	if err := r.ParseForm(); err != nil {
		sendHTML(w, 500, web.TwoFASetupPage(s.siteTitle, "请求处理失败", "", enabled))
		return
	}

	cookies := auth.ParseCookies(r.Header.Get("Cookie"))
	setupUser, secret, ok := auth.ValidateSetupToken(cookies[s.cookieNames.TOTASetup()], s.sessionSecret)
	if !ok || setupUser != username {
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
	w.Header().Add("Set-Cookie", s.cookieNames.ClearSetupCookie())
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
	setupUser, secret, ok := auth.ValidateSetupToken(cookies[s.cookieNames.TOTASetup()], s.sessionSecret)
	if !ok || setupUser != session.UserID {
		http.Error(w, "invalid setup", http.StatusBadRequest)
		return
	}
	png, err := qrcode.Encode(auth.TOTPURI(session.UserID, secret), qrcode.Medium, 256)
	if err != nil {
		http.Error(w, "qr error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
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
