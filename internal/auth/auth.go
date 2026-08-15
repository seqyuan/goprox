package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	SessionCookieName = "goprox_session"
	TOTACookieName    = "goprox_2fa"       // pending 2FA token after password step
	TOTASetupCookie   = "goprox_2fa_setup" // pending secret during enrollment
	RouteCookieName   = "goprox_route"
	RouteCookiePrefix = "goprox_route_" // Prefix for service-specific route cookies
)

// SessionResult holds session validation result.
type SessionResult struct {
	Valid     bool
	UserID    string
	ExpiresAt int64 // Unix timestamp when session expires
}

// base64URLEncode encodes bytes to URL-safe base64 without padding.
func base64URLEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

// base64URLDecode decodes URL-safe base64.
func base64URLDecode(s string) ([]byte, error) {
	// Add padding
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// bcryptPasswordMax is bcrypt's input limit (72 bytes); longer passwords are
// truncated consistently on both hash and verify, so login still works.
const bcryptPasswordMax = 72

// HashPassword hashes a password with bcrypt (cost 10). New accounts and
// password resets use bcrypt; legacy SHA-256 hashes remain verifiable via
// VerifyPassword's fallback path.
func HashPassword(password string) string {
	pw := []byte(password)
	if len(pw) > bcryptPasswordMax {
		pw = pw[:bcryptPasswordMax]
	}
	hash, err := bcrypt.GenerateFromPassword(pw, bcrypt.DefaultCost)
	if err != nil {
		// Unreachable for valid input; keep a SHA-256 hash so the account
		// stays locked rather than crashing the CLI.
		h := sha256.Sum256(pw)
		return hex.EncodeToString(h[:])
	}
	return string(hash)
}

// VerifyPassword checks a password against a stored hash. bcrypt hashes
// (starting with "$2") are verified with bcrypt; 64-char hex strings are
// treated as legacy unsalted SHA-256 hashes for backward compatibility.
func VerifyPassword(password, expectedHash string) bool {
	if strings.HasPrefix(expectedHash, "$2") {
		pw := []byte(password)
		if len(pw) > bcryptPasswordMax {
			pw = pw[:bcryptPasswordMax]
		}
		return bcrypt.CompareHashAndPassword([]byte(expectedHash), pw) == nil
	}

	// Legacy unsalted SHA-256 hex (pre-bcrypt format), verified directly:
	// HashPassword now returns bcrypt and must not be reused here.
	h := sha256.Sum256([]byte(password))
	hash := hex.EncodeToString(h[:])
	expected, err := hex.DecodeString(expectedHash)
	if err != nil {
		return false
	}
	actual, err := hex.DecodeString(hash)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(expected, actual) == 1
}

// dummyPasswordHash is a bcrypt hash of a fixed string, used only to equalize
// login latency for unknown usernames. Verifying against it costs the same as
// verifying a real account, so response timing cannot be used to enumerate
// valid usernames. It never matches a real password.
const dummyPasswordHash = "$2a$10$d2yql/LCIBoPfN3skgZhW.Nb5TDZ4UOKEJAsQWyZ7i/nP4bOlnSq6"

// VerifyPasswordTimingSafe verifies a password against a stored hash, but runs
// a bcrypt comparison even when the hash is missing (unknown user), so login
// latency does not reveal whether a username exists.
func VerifyPasswordTimingSafe(password, expectedHash string) bool {
	if expectedHash == "" {
		pw := []byte(password)
		if len(pw) > bcryptPasswordMax {
			pw = pw[:bcryptPasswordMax]
		}
		// Burn the same CPU as a real bcrypt verify without accepting anything.
		bcrypt.CompareHashAndPassword([]byte(dummyPasswordHash), pw)
		return false
	}
	return VerifyPassword(password, expectedHash)
}

// SessionRev derives a short per-account revision from the stored password
// hash. The session token embeds this revision, so changing the password
// changes the revision and invalidates all previously-issued sessions.
func SessionRev(passwordHash string) string {
	if passwordHash == "" {
		return ""
	}
	h := sha256.Sum256([]byte(passwordHash))
	return hex.EncodeToString(h[:8]) // 16 hex chars
}

// CreateSessionToken creates a signed session token bound to a per-account
// revision (derived from the password hash). The revision is part of the
// signed payload, so a token cannot be replayed after the password changes.
func CreateSessionToken(userID, secret string, ttlSec int, rev string) string {
	expiry := time.Now().Unix() + int64(ttlSec)
	payload := fmt.Sprintf("%s|%d|%s", userID, expiry, rev)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	token := fmt.Sprintf("%s|%s", payload, sig)
	return base64URLEncode([]byte(token))
}

// SessionTokenParts decodes a session token and returns its userID, expiry and
// revision WITHOUT verifying the signature. Callers use the userID to look up
// the current revision, then call ValidateSessionToken to verify.
func SessionTokenParts(token string) (userID string, expiry int64, rev string, err error) {
	decoded, err := base64URLDecode(token)
	if err != nil {
		return "", 0, "", err
	}
	parts := strings.SplitN(string(decoded), "|", 4)
	if len(parts) != 4 {
		return "", 0, "", fmt.Errorf("malformed session token")
	}
	expiry, err = strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", 0, "", err
	}
	return parts[0], expiry, parts[2], nil
}

// ValidateSessionToken validates a session token against the account's current
// revision. The signature is recomputed over the CURRENT revision, so a token
// issued before a password change (an older revision) fails verification.
func ValidateSessionToken(token, secret, currentRev string) SessionResult {
	userID, expiry, _, err := SessionTokenParts(token)
	if err != nil || userID == "" {
		return SessionResult{Valid: false}
	}

	payload := fmt.Sprintf("%s|%d|%s", userID, expiry, currentRev)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	// Extract the token's signature for a constant-time comparison.
	decoded, err := base64URLDecode(token)
	if err != nil {
		return SessionResult{Valid: false}
	}
	parts := strings.SplitN(string(decoded), "|", 4)
	if len(parts) != 4 {
		return SessionResult{Valid: false}
	}
	sig := parts[3]

	if subtle.ConstantTimeCompare([]byte(sig), []byte(expectedSig)) != 1 {
		return SessionResult{Valid: false}
	}

	now := time.Now().Unix()
	if now > expiry {
		return SessionResult{Valid: false}
	}

	return SessionResult{
		Valid:     true,
		UserID:    userID,
		ExpiresAt: expiry,
	}
}

// ParseCookies parses cookie header into a map.
func ParseCookies(cookieHeader string) map[string]string {
	cookies := make(map[string]string)
	if cookieHeader == "" {
		return cookies
	}
	for _, pair := range strings.Split(cookieHeader, ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		idx := strings.Index(pair, "=")
		if idx == -1 {
			continue
		}
		key := strings.TrimSpace(pair[:idx])
		val := strings.TrimSpace(pair[idx+1:])
		if key != "" {
			cookies[key] = val
		}
	}
	return cookies
}

// trustedProxy holds the CIDR of a trusted reverse proxy in front of the
// gateway (configured via ConfigureTrustedProxy). When nil, forwarded headers
// are ignored because any direct client can spoof them.
var trustedProxy *net.IPNet

// ConfigureTrustedProxy sets the CIDR (or single IP) of a trusted reverse
// proxy. Only requests arriving from this proxy have their X-Forwarded-*
// headers honored (for client IP and HTTPS detection); with an empty or
// invalid value, forwarded headers are ignored entirely.
func ConfigureTrustedProxy(cidr string) {
	trustedProxy = nil
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return
	}
	if _, ipnet, err := net.ParseCIDR(cidr); err == nil {
		trustedProxy = ipnet
		return
	}
	if ip := net.ParseIP(cidr); ip != nil {
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		trustedProxy = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
	}
}

// fromTrustedProxy reports whether the request's peer address is inside the
// configured trusted-proxy range.
func fromTrustedProxy(r *http.Request) bool {
	if trustedProxy == nil {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && trustedProxy.Contains(ip)
}

// IsSecureRequest checks if the request came over TLS. X-Forwarded-Proto is
// only honored when the request arrived from the configured trusted proxy.
func IsSecureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if !fromTrustedProxy(r) {
		return false
	}
	proto := r.Header.Get("X-Forwarded-Proto")
	return strings.HasPrefix(strings.ToLower(proto), "https")
}

// SetSessionCookie creates a Set-Cookie header value for the session, bound
// to the account's current password-hash revision.
func SetSessionCookie(secret string, ttlSec int, userID, rev string, secure bool) string {
	token := CreateSessionToken(userID, secret, ttlSec, rev)
	expires := time.Now().Add(time.Duration(ttlSec) * time.Second).UTC().Format(time.RFC1123)
	secureFlag := ""
	if secure {
		secureFlag = "; Secure"
	}
	return fmt.Sprintf("%s=%s; HttpOnly; Path=/; SameSite=Lax; Expires=%s%s",
		SessionCookieName, token, expires, secureFlag)
}

// ClearSessionCookie creates a Set-Cookie header to clear the session.
func ClearSessionCookie() string {
	return fmt.Sprintf("%s=; HttpOnly; Path=/; SameSite=Lax; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
		SessionCookieName)
}

// ClearRouteCookies returns the Set-Cookie headers needed to clear every
// route cookie present in the request's Cookie header. Route cookies persist
// beyond logout and would otherwise keep forwarding bare paths to backends.
func ClearRouteCookies(cookieHeader string) []string {
	var out []string
	for name := range ParseCookies(cookieHeader) {
		if name == RouteCookieName || strings.HasPrefix(name, RouteCookiePrefix) {
			out = append(out, fmt.Sprintf("%s=; HttpOnly; Path=/; SameSite=Lax; Expires=Thu, 01 Jan 1970 00:00:00 GMT", name))
		}
	}
	return out
}

// SetRouteCookie creates a Set-Cookie for tracking proxy route.
// Uses a service-specific cookie name to avoid conflicts between services.
// The cookie is scoped to "/" so it's available for all request paths.
func SetRouteCookie(prefix string) string {
	// Create a unique cookie name based on the service prefix
	// This prevents cookie conflicts when using multiple services
	cookieName := RouteCookieNameForPrefix(prefix)
	return fmt.Sprintf("%s=%s; HttpOnly; Path=/; SameSite=Lax",
		cookieName, prefix)
}

// SetRouteCookies returns the Set-Cookie headers written when a service is
// visited: a service-specific cookie (so multiple services coexist without
// clobbering each other) plus the global route cookie, which records the most
// recently visited service and serves as the fallback when the specific
// cookies cannot disambiguate a bare request.
func SetRouteCookies(prefix string) []string {
	return []string{
		SetRouteCookie(prefix),
		fmt.Sprintf("%s=%s; HttpOnly; Path=/; SameSite=Lax", RouteCookieName, prefix),
	}
}

// RouteCookieNameForPrefix generates a cookie name for a specific service prefix.
func RouteCookieNameForPrefix(prefix string) string {
	if prefix == "" {
		return RouteCookieName
	}
	// Use hash to create a stable, short identifier
	h := sha256.Sum256([]byte(prefix))
	return RouteCookiePrefix + hex.EncodeToString(h[:4]) // 8 chars
}

// GetRouteCookieForRequest extracts the route prefix that belongs to this request.
// Global route cookies are intentionally not used for "/" because that is the dashboard.
// If multiple service cookies exist, the request or referer must disambiguate them.
func GetRouteCookieForRequest(cookieHeader, requestPath, referer string) string {
	if requestPath == "/" {
		return ""
	}

	routes := routeCookieValues(cookieHeader)
	if len(routes) == 0 {
		return ""
	}

	if route := bestRouteForPath(routes, requestPath); route != "" {
		return route
	}

	refPath := ""
	if referer != "" {
		if u, err := url.Parse(referer); err == nil {
			refPath = u.Path
		}
	}
	if route := bestRouteForPath(routes, refPath); route != "" {
		return route
	}

	if len(routes) == 1 {
		return routes[0]
	}

	// Multiple services are in play and neither the request path nor the
	// Referer disambiguates them (e.g. an absolute-path asset like /_next/…
	// or /api/… fetched without a Referer). Fall back to the most recently
	// visited service (the global route cookie) instead of returning "" and
	// 404ing the page.
	if recent := ParseCookies(cookieHeader)[RouteCookieName]; recent != "" {
		return recent
	}
	return ""
}

func routeCookieValues(cookieHeader string) []string {
	cookies := ParseCookies(cookieHeader)
	seen := make(map[string]bool)
	routes := make([]string, 0, len(cookies))

	addRoute := func(route string) {
		if route == "" || seen[route] {
			return
		}
		seen[route] = true
		routes = append(routes, route)
	}

	addRoute(cookies[RouteCookieName])
	for name, value := range cookies {
		if strings.HasPrefix(name, RouteCookiePrefix) {
			addRoute(value)
		}
	}
	return routes
}

func bestRouteForPath(routes []string, requestPath string) string {
	if requestPath == "" {
		return ""
	}
	best := ""
	for _, route := range routes {
		prefix := strings.TrimRight(route, "/")
		if requestPath == prefix || strings.HasPrefix(requestPath, prefix+"/") {
			if len(route) > len(best) {
				best = route
			}
		}
	}
	return best
}

// ShouldRefreshSession checks if a session should be refreshed.
// Returns true if the session is valid but will expire within 25% of its TTL.
func ShouldRefreshSession(session SessionResult, ttlSec int) bool {
	if !session.Valid || session.ExpiresAt == 0 {
		return false
	}

	now := time.Now().Unix()
	timeRemaining := session.ExpiresAt - now
	refreshThreshold := int64(float64(ttlSec) * 0.25)

	return timeRemaining > 0 && timeRemaining < refreshThreshold
}

// ClientIP extracts the client IP from a request. Forwarded headers are only
// trusted when the request arrives from the configured trusted proxy;
// otherwise the TCP peer address is used (X-Forwarded-* is spoofable by any
// direct client).
func ClientIP(r *http.Request) string {
	if fromTrustedProxy(r) {
		// Check X-Forwarded-For first
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[0])
		}
		// Check X-Real-IP
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return xri
		}
	}
	// Fall back to the TCP peer address.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return host
}

// SameOriginRequest reports whether the request's Origin header (when
// present) matches the origin the browser is talking to. Browsers always
// send Origin on POST/PUT/DELETE, so cross-site requests (the CSRF vector)
// are rejected while same-origin and non-browser (no Origin) requests pass.
// Any http(s) scheme is accepted: behind a TLS-terminating reverse proxy the
// browser's scheme (https) legitimately differs from the gateway's (http).
func SameOriginRequest(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		// Non-browser clients (curl, scripts) send no Origin; without a
		// browser context there is no CSRF risk, and they still need the
		// session cookie to be authorized.
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

// ---- TOTP (RFC 6238) two-factor authentication ----

const (
	// totpPeriod is the time-step size in seconds (RFC 6238 default).
	totpPeriod = 30
	// totpDigits is the number of digits in the one-time code.
	totpDigits = 6
	// totpIssuer is shown as the account issuer in authenticator apps.
	totpIssuer = "GoProx"
)

// GenerateTOTPSecret returns a new random 20-byte secret encoded as
// base32 (no padding) — the format authenticator apps expect.
func GenerateTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// TOTPURI builds the otpauth:// provisioning URI for authenticator apps
// (Google Authenticator, Authy, 1Password, …).
func TOTPURI(account, secret string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
		totpIssuer, account, secret, totpIssuer, totpDigits, totpPeriod)
}

// VerifyTOTP checks a 6-digit code against a base32 secret, accepting the
// current, previous and next 30-second window (clock drift tolerance).
func VerifyTOTP(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil || len(key) == 0 {
		return false
	}

	counter := uint64(now.Unix() / totpPeriod)
	for _, c := range []uint64{counter - 1, counter, counter + 1} {
		if totpCode(key, c) == code {
			return true
		}
	}
	return false
}

// totpCode computes the HOTP value (truncated to 6 digits) for a counter.
func totpCode(key []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	h := mac.Sum(nil)
	offset := h[len(h)-1] & 0x0f
	binaryValue := (binary.BigEndian.Uint32(h[offset:offset+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%0*d", totpDigits, binaryValue)
}

// ---- pending 2FA token (issued after the password step) ----

// CreatePendingToken signs a short-lived token proving the password step
// already succeeded, so the 2FA step can be entered without re-typing the
// password. The "2fa" domain prefix keeps it distinct from session tokens.
func CreatePendingToken(userID, secret string, ttlSec int) string {
	expiry := time.Now().Unix() + int64(ttlSec)
	payload := fmt.Sprintf("2fa|%s|%d", userID, expiry)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	return base64URLEncode([]byte(payload + "|" + sig))
}

// ValidatePendingToken verifies a pending-2FA token and returns the username.
func ValidatePendingToken(token, secret string) (string, bool) {
	decoded, err := base64URLDecode(token)
	if err != nil {
		return "", false
	}
	parts := strings.SplitN(string(decoded), "|", 4)
	if len(parts) != 4 || parts[0] != "2fa" {
		return "", false
	}
	userID, expiryStr, sig := parts[1], parts[2], parts[3]
	expiry, err := strconv.ParseInt(expiryStr, 10, 64)
	if err != nil || time.Now().Unix() > expiry {
		return "", false
	}

	payload := fmt.Sprintf("2fa|%s|%d", userID, expiry)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	expected := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(sig), []byte(expected)) != 1 {
		return "", false
	}
	return userID, true
}

// SetPendingCookie creates a Set-Cookie header for the pending 2FA token.
func SetPendingCookie(secret string, ttlSec int, userID string, secure bool) string {
	token := CreatePendingToken(userID, secret, ttlSec)
	expires := time.Now().Add(time.Duration(ttlSec) * time.Second).UTC().Format(time.RFC1123)
	secureFlag := ""
	if secure {
		secureFlag = "; Secure"
	}
	return fmt.Sprintf("%s=%s; HttpOnly; Path=/; SameSite=Lax; Expires=%s%s",
		TOTACookieName, token, expires, secureFlag)
}

// ClearPendingCookie creates a Set-Cookie header to clear the pending token.
func ClearPendingCookie() string {
	return fmt.Sprintf("%s=; HttpOnly; Path=/; SameSite=Lax; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
		TOTACookieName)
}

// ---- pending TOTP secret (held during enrollment, not yet persisted) ----

// CreateSetupToken signs a freshly generated TOTP secret so the enrollment
// flow can show the QR code and verify a code without any server-side state.
func CreateSetupToken(secret, sessionSecret string, ttlSec int) string {
	expiry := time.Now().Unix() + int64(ttlSec)
	payload := fmt.Sprintf("setup|%s|%d", secret, expiry)
	mac := hmac.New(sha256.New, []byte(sessionSecret))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	return base64URLEncode([]byte(payload + "|" + sig))
}

// ValidateSetupToken verifies a setup token and returns the pending secret.
func ValidateSetupToken(token, sessionSecret string) (string, bool) {
	decoded, err := base64URLDecode(token)
	if err != nil {
		return "", false
	}
	parts := strings.SplitN(string(decoded), "|", 4)
	if len(parts) != 4 || parts[0] != "setup" {
		return "", false
	}
	secret, expiryStr, sig := parts[1], parts[2], parts[3]
	expiry, err := strconv.ParseInt(expiryStr, 10, 64)
	if err != nil || time.Now().Unix() > expiry {
		return "", false
	}

	payload := fmt.Sprintf("setup|%s|%d", secret, expiry)
	mac := hmac.New(sha256.New, []byte(sessionSecret))
	mac.Write([]byte(payload))
	expected := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(sig), []byte(expected)) != 1 {
		return "", false
	}
	return secret, true
}

// SetSetupCookie creates a Set-Cookie header for the pending setup secret.
func SetSetupCookie(secret, sessionSecret string, ttlSec int, secure bool) string {
	token := CreateSetupToken(secret, sessionSecret, ttlSec)
	expires := time.Now().Add(time.Duration(ttlSec) * time.Second).UTC().Format(time.RFC1123)
	secureFlag := ""
	if secure {
		secureFlag = "; Secure"
	}
	return fmt.Sprintf("%s=%s; HttpOnly; Path=/; SameSite=Lax; Expires=%s%s",
		TOTASetupCookie, token, expires, secureFlag)
}

// ClearSetupCookie creates a Set-Cookie header to clear the pending secret.
func ClearSetupCookie() string {
	return fmt.Sprintf("%s=; HttpOnly; Path=/; SameSite=Lax; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
		TOTASetupCookie)
}
