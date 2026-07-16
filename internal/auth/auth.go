package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	SessionCookieName = "goprox_session"
	RouteCookieName   = "goprox_route"
)

// SessionResult holds session validation result.
type SessionResult struct {
	Valid      bool
	UserID     string
	ExpiresAt  int64  // Unix timestamp when session expires
	IssuedAt   int64  // Unix timestamp when session was created
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

// HashPassword hashes a password with SHA-256.
func HashPassword(password string) string {
	h := sha256.Sum256([]byte(password))
	return hex.EncodeToString(h[:])
}

// VerifyPassword compares a password against a SHA-256 hash.
func VerifyPassword(password, expectedHash string) bool {
	hash := HashPassword(password)
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

// CreateSessionToken creates a signed session token.
func CreateSessionToken(userID, secret string, ttlSec int) string {
	expiry := time.Now().Unix() + int64(ttlSec)
	payload := fmt.Sprintf("%s|%d", userID, expiry)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	token := fmt.Sprintf("%s|%s", payload, sig)
	return base64URLEncode([]byte(token))
}

// ValidateSessionToken validates a session token.
func ValidateSessionToken(token, secret string) SessionResult {
	decoded, err := base64URLDecode(token)
	if err != nil {
		return SessionResult{Valid: false}
	}

	parts := strings.SplitN(string(decoded), "|", 3)
	if len(parts) != 3 {
		return SessionResult{Valid: false}
	}

	userID, expiryStr, sig := parts[0], parts[1], parts[2]
	expiry, err := strconv.ParseInt(expiryStr, 10, 64)
	if err != nil || userID == "" {
		return SessionResult{Valid: false}
	}

	payload := fmt.Sprintf("%s|%s", userID, expiryStr)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if subtle.ConstantTimeCompare([]byte(sig), []byte(expectedSig)) != 1 {
		return SessionResult{Valid: false}
	}

	now := time.Now().Unix()
	if now > expiry {
		return SessionResult{Valid: false}
	}

	// Calculate when this token was issued (approximation)
	issuedAt := expiry - int64(86400) // Assume default TTL if not stored

	return SessionResult{
		Valid:     true,
		UserID:    userID,
		ExpiresAt: expiry,
		IssuedAt:  issuedAt,
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

// GetSessionFromCookies extracts and validates session from cookies.
func GetSessionFromCookies(cookieHeader, secret string) SessionResult {
	cookies := ParseCookies(cookieHeader)
	token := cookies[SessionCookieName]
	if token == "" {
		return SessionResult{Valid: false}
	}
	return ValidateSessionToken(token, secret)
}

// IsSecureRequest checks if the request came over TLS.
func IsSecureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	proto := r.Header.Get("X-Forwarded-Proto")
	if strings.HasPrefix(strings.ToLower(proto), "https") {
		return true
	}
	return false
}

// SetSessionCookie creates a Set-Cookie header value for the session.
func SetSessionCookie(secret string, ttlSec int, userID string, secure bool) string {
	token := CreateSessionToken(userID, secret, ttlSec)
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

// SetRouteCookie creates a Set-Cookie for tracking proxy route.
// The cookie is scoped to the service path to avoid conflicts between services.
func SetRouteCookie(prefix string) string {
	// Scope cookie to the service path to prevent cross-service conflicts
	path := prefix
	if path == "" {
		path = "/"
	}
	return fmt.Sprintf("%s=%s; HttpOnly; Path=%s; SameSite=Lax",
		RouteCookieName, prefix, path)
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

// ClientIP extracts the client IP from a request.
func ClientIP(r *http.Request) string {
	// Check X-Forwarded-For first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Fall back to RemoteAddr
	host := r.RemoteAddr
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		return host[:idx]
	}
	return host
}
