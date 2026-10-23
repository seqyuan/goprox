package proxy

import (
	"net/http"
	"strings"
)

// RewriteSetCookie rewrites a backend Set-Cookie so the browser can actually
// use it under the gateway's origin and path prefix:
//
//   - Domain is dropped: the backend's domain (often 127.0.0.1 / localhost)
//     does not match the gateway the browser talks to, so the browser would
//     reject or mis-scope the cookie. Dropping it makes the cookie host-only on
//     the gateway origin.
//   - Path is re-rooted under the service prefix so cookie names cannot collide
//     across services/users that share the gateway origin. Pass proxyPath == ""
//     to leave Path untouched (bare/root-path access, where the browser is not
//     under the proxy prefix and narrowing Path would stop the cookie being sent).
//   - Secure is cleared when the browser reached the gateway over plain HTTP;
//     otherwise the browser silently drops the cookie and any session (e.g.
//     dsh's 303 + Set-Cookie handshake) never sticks.
//   - The __Host- / __Secure- name prefixes are stripped once the rewritten
//     cookie can no longer satisfy their invariants (both require Secure;
//     __Host- additionally requires Path=/ and no Domain).
//
// Malformed cookies are returned untouched: passing an opaque value through is
// safer than dropping a session.
func RewriteSetCookie(raw, proxyPath string, clientSecure bool) string {
	c, err := http.ParseSetCookie(raw)
	if err != nil || c == nil || c.Name == "" {
		return raw
	}
	c.Domain = ""
	if proxyPath != "" {
		c.Path = rewriteCookiePath(c.Path, proxyPath)
	}
	if !clientSecure {
		c.Secure = false
		// Browsers reject SameSite=None without Secure, so a backend cookie
		// intended for cross-site use would be silently dropped over plain
		// HTTP. Fall back to Lax, the most permissive value HTTP supports.
		if c.SameSite == http.SameSiteNoneMode {
			c.SameSite = http.SameSiteLaxMode
		}
	}
	// __Host- requires Secure + Path=/ + no Domain; __Secure- requires Secure.
	// Strip the prefix once the rewrite breaks the invariant (a reserved prefix
	// on a cookie the browser would reject would silently lose the session).
	if strings.HasPrefix(c.Name, "__Host-") && (c.Path != "/" || !c.Secure) {
		c.Name = strings.TrimPrefix(c.Name, "__Host-")
	} else if strings.HasPrefix(c.Name, "__Secure-") && !c.Secure {
		c.Name = strings.TrimPrefix(c.Name, "__Secure-")
	}
	out := c.String()
	if out == "" {
		return raw
	}
	return out
}

// rewriteCookiePath scopes a backend cookie path under the proxy prefix. A
// backend path of "/" (or empty) maps to the prefix root ("/proxy/u/svc/");
// "/app" maps to "/proxy/u/svc/app".
func rewriteCookiePath(backendPath, proxyPath string) string {
	if !strings.HasSuffix(proxyPath, "/") {
		proxyPath += "/"
	}
	if backendPath == "" || backendPath == "/" {
		return proxyPath
	}
	if !strings.HasPrefix(backendPath, "/") {
		backendPath = "/" + backendPath
	}
	return strings.TrimSuffix(proxyPath, "/") + backendPath
}
