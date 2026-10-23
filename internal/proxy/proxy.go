package proxy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	pathpkg "path"
	"strconv"
	"strings"

	"github.com/seqyuan/goprox/internal/auth"
	"github.com/seqyuan/goprox/internal/config"
	"github.com/seqyuan/goprox/internal/rate"
)

// stripGatewayCookie removes gateway cookies from a Cookie header.
func stripGatewayCookie(cookieHeader string) string {
	parts := strings.Split(cookieHeader, ";")
	kept := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name := part
		if idx := strings.Index(part, "="); idx != -1 {
			name = part[:idx]
		}
		if auth.IsGatewayCookieName(name) {
			continue
		}
		kept = append(kept, part)
	}
	return strings.Join(kept, "; ")
}

// ProxyForwardContext holds forwarding metadata.
// ForwardMode selects how browser paths map to the backend. The zero value
// preserves the canonical /proxy/<user>/<service> prefix behavior.
type ForwardMode int

const (
	// ForwardPrefix is the canonical /proxy/<user>/<service>/... mode.
	ForwardPrefix ForwardMode = iota
	// ForwardAsIs keeps the browser path unchanged (default_service, Referer,
	// route cookie forwarding).
	ForwardAsIs
	// ForwardVHost serves a dedicated hostname at the root path.
	ForwardVHost
)

type ProxyForwardContext struct {
	Prefix   string
	Base     string // <base href> to inject: directory of the served document
	Mode     ForwardMode
	ClientIP string
	Proto    string
	Host     string
	Username string          // authenticated session user (lightweight SSO identity)
	SSO      config.SSOState // lightweight SSO: identity header name + optional HMAC key
	// Bootstrap enables the upstream session handshake for backends that gate
	// their UI behind a startup token (e.g. dsh). Populated from the service in
	// NewReverseProxy; nil disables it.
	Bootstrap *config.AuthBootstrapConfig
	// OriginalPath is the browser-visible request URI (path?query) before the
	// backend path rewrite, used to build the bootstrap redirect back to the
	// gateway origin (never the loopback backend address).
	OriginalPath string
}

// BuildProxyForwardContext creates forwarding context from a request and match.
func BuildProxyForwardContext(r *http.Request, username, servicePath string, legacy bool) ProxyForwardContext {
	prefix := "/proxy/" + username + servicePath
	if legacy {
		prefix = "/proxy" + servicePath
	}
	return ProxyForwardContext{
		Prefix:       prefix,
		Base:         prefix + "/",
		ClientIP:     auth.ClientIP(r),
		Proto:        proto(r),
		Host:         r.Host,
		Username:     username,
		OriginalPath: r.URL.RequestURI(),
	}
}

// BaseForPath computes the <base href> (a directory URL with trailing slash)
// that relative links in a document served at the given remaining path should
// resolve against. For a page at /proxy/user/svc/report/page.html the base is
// /proxy/user/svc/report/; for the service root (remaining "/") it is the
// service prefix. The result is URL-escaped.
func BaseForPath(prefix, remaining string) string {
	full := prefix + remaining
	if !strings.HasSuffix(full, "/") {
		full = pathpkg.Dir(full)
	}
	full = strings.TrimSuffix(full, "/") + "/"
	return (&url.URL{Path: full}).EscapedPath()
}

func proto(r *http.Request) string {
	if auth.IsSecureRequest(r) {
		return "https"
	}
	return "http"
}

// SSOSignaturePrefix domain-separates the HMAC input so a signature computed
// for this scheme cannot be replayed against a different scheme that reuses
// the same secret. Backends verify: hmac.Equal(header, HMAC-SHA256(secret,
// SSOSignaturePrefix+username)) — the header value is base64url (unpadded).
const SSOSignaturePrefix = "goprox-sso:v1:"

// identityHeaderNames are well-known "authenticated user" headers that
// backends commonly trust (JupyterHub, oauth2-proxy, nginx auth_request,
// Apache mod_authnz_forwarded, ...). They are stripped unconditionally: the
// gateway is the only entity that may vouch for an identity, so a backend
// trusting any of these cannot be spoofed through the gateway — even when
// the admin's SSO header has a different name, or SSO is disabled.
var identityHeaderNames = []string{
	"X-Authenticated-User",
	"X-Forwarded-User",
	"X-Auth-Request-User",
	"Remote-User",
	"Remote_User",
}

// applySSOHeaders sets (or strips) authenticated-user identity headers on an
// outbound proxied request.
//
// When SSO is configured, UserHeader carries the username from the verified
// session — never from the browser: any client-supplied value is deleted
// first, then replaced, so a forged header cannot reach the backend. When
// HMACSecret is set, UserHeader+"-Signature" additionally carries an
// HMAC-SHA256 signature of SSOSignaturePrefix+username so the backend can
// verify the identity without depending on network isolation alone.
func applySSOHeaders(out http.Header, sso config.SSOState, username string) {
	for _, h := range identityHeaderNames {
		out.Del(h)
		out.Del(h + "-Signature")
	}
	if sso.UserHeader == "" || !config.IsValidHeaderName(sso.UserHeader) {
		return
	}
	out.Del(sso.UserHeader)
	out.Del(sso.UserHeader + "-Signature")
	if username == "" {
		return
	}
	out.Set(sso.UserHeader, username)
	if sso.HMACSecret != "" {
		mac := hmac.New(sha256.New, []byte(sso.HMACSecret))
		mac.Write([]byte(SSOSignaturePrefix + username))
		out.Set(sso.UserHeader+"-Signature", base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	}
}

// originAuthorityMatches reports whether the Origin header's authority equals
// the given gateway authority (hostname and port, WHATWG-normalized). Only
// same-origin browser requests through the gateway are candidates for the
// Origin rewrite; a third-party Origin (a CORS client on another site) must
// pass through untouched.
func originAuthorityMatches(origin, gatewayHost string) bool {
	o, err := url.Parse(origin)
	if err != nil || o.Host == "" {
		return false
	}
	g, err := url.Parse("http://" + gatewayHost)
	if err != nil || g.Host == "" {
		return false
	}
	return strings.EqualFold(o.Host, g.Host)
}

// maxInjectHTML caps how much of an HTML body we buffer for <base>
// injection. Known-length responses larger than this are passed through
// untouched; unknown-length (chunked) responses are read up to this cap
// and the remainder streamed, so memory stays bounded either way.
// (Package-level var so tests can shrink it to exercise the cap.)
var maxInjectHTML int64 = 8 << 20

// backendAuthority returns the backend URL authority, bracketing IPv6
// literals correctly (net.JoinHostPort); naive host+":"+port produces an
// invalid Host/Origin for addresses such as ::1.
func backendAuthority(svc *config.ServiceConfig) string {
	host := svc.Host
	// A hand-edited config may spell an IPv6 literal as [::1]; JoinHostPort
	// adds its own brackets, so strip a pre-existing pair first.
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	return net.JoinHostPort(host, strconv.Itoa(svc.Port))
}

// NewReverseProxy creates a configured reverse proxy for a service.
func NewReverseProxy(svc *config.ServiceConfig, fc ProxyForwardContext) *httputil.ReverseProxy {
	target := &url.URL{
		Scheme: "http",
		Host:   backendAuthority(svc),
	}

	// Carry the service's session-bootstrap config into the response hook.
	fc.Bootstrap = svc.AuthBootstrap

	backendPath := svc.BackendPath

	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = target.Host

			// Map frontend remaining path onto an optional backend base path.
			if backendPath != "" {
				pr.Out.URL.Path = joinBackendPath(backendPath, pr.Out.URL.Path)
			}
			// Clear RawPath so the (possibly rewritten) Path is what goes on
			// the wire. SetURL may leave a stale RawPath when the original
			// request had encoded characters; without clearing it, EscapedPath
			// would prefer the stale value over the rewritten Path.
			pr.Out.URL.RawPath = ""

			// HTML bodies must reach ModifyResponse uncompressed so <base>
			// injection does not corrupt a gzip stream. For likely-static
			// assets (JS/CSS/images/fonts/…), which never need injection, we
			// keep the browser's Accept-Encoding so end-to-end compression is
			// preserved. Everything else (HTML pages, extension-less APIs)
			// strips it; the Transport then requests gzip itself and
			// transparently decompresses before injection.
			if !isStaticAssetPath(pr.Out.URL.Path) {
				pr.Out.Header.Del("Accept-Encoding")
			}

			// Strip gateway cookies. This includes the 2FA pending/setup cookies:
			// the setup cookie carries the not-yet-persisted TOTP secret, so
			// forwarding it to a backend would leak a future second factor.
			if cookie := pr.In.Header.Get("Cookie"); cookie != "" {
				if stripped := stripGatewayCookie(cookie); stripped != "" {
					pr.Out.Header.Set("Cookie", stripped)
				} else {
					pr.Out.Header.Del("Cookie")
				}
			}

			// Forwarded headers: send only the peer address computed by
			// ClientIP. A client-supplied X-Forwarded-For must not be passed
			// through, otherwise a backend that trusts XFF (for logging or
			// IP-based access control) would see an attacker-controlled source.
			pr.Out.Header.Set("X-Forwarded-For", fc.ClientIP)
			pr.Out.Header.Set("X-Real-IP", fc.ClientIP)
			pr.Out.Header.Set("X-Forwarded-Proto", fc.Proto)
			pr.Out.Header.Set("X-Forwarded-Host", fc.Host)
			// Other proxy-metadata headers are commonly trusted by frameworks
			// (e.g. X-Original-URL/X-Rewrite-URL auth bypasses, Forwarded). They
			// must never come from the browser unchanged.
			for _, h := range []string{
				"Forwarded", "X-Original-URL", "X-Rewrite-URL",
				"X-Forwarded-Port", "X-Forwarded-Server",
			} {
				pr.Out.Header.Del(h)
			}
			if fc.Mode == ForwardPrefix {
				pr.Out.Header.Set("X-Forwarded-Prefix", fc.Prefix)
			} else {
				// A vhost owns its host root; as-is forwarding is mounted at the
				// gateway root. Neither is under the canonical /proxy/ prefix.
				pr.Out.Header.Del("X-Forwarded-Prefix")
			}

			// Lightweight SSO: carry the authenticated session user to
			// backends that opt in, and never let the browser supply an
			// identity the gateway did not vouch for (see applySSOHeaders).
			applySSOHeaders(pr.Out.Header, fc.SSO, fc.Username)

			// The Host header was rewritten to the backend target above, so a
			// browser-sent Origin (the gateway's authority) would mismatch and
			// fail backends that enforce a same-origin Host/Origin check (e.g.
			// dsh's /api trust fence, Jupyter CSRF). For same-origin browser
			// requests — Origin host equals the gateway authority the browser
			// addressed — rewrite Origin to the backend's own authority so the
			// request looks same-origin to the backend, exactly as if the
			// browser had talked to it directly. Third-party Origins (CORS
			// clients calling the proxied API from another site) are left
			// untouched so backend CORS semantics stay intact.
			if origin := pr.In.Header.Get("Origin"); origin != "" && originAuthorityMatches(origin, fc.Host) {
				pr.Out.Header.Set("Origin", fc.Proto+"://"+target.Host)
			}

			// Throttle the request body (upload) to the per-service cap. The
			// transport reads pr.Out.Body, so wrapping it here limits the rate
			// at which the client's upload reaches the backend.
			if svc.BWLimit > 0 && pr.Out.Body != nil {
				pr.Out.Body = rate.NewLimitedReaderContext(pr.Out.Body, svc.BWLimit, pr.Out.Context())
			}
		},
		ModifyResponse: func(resp *http.Response) (retErr error) {
			// 101 Switching Protocols hands the raw connection to the upgrade
			// tunnel (WebSocket): ReverseProxy requires resp.Body to stay the
			// io.ReadWriteCloser the transport produced. Wrapping it with a
			// rate limiter would break the upgrade (and throttling a live
			// tunnel is meaningless anyway), so pass it through untouched.
			if resp.StatusCode == http.StatusSwitchingProtocols {
				return nil
			}

			// Upstream session bootstrap (e.g. dsh): a local-first backend may
			// answer an unauthenticated page request with 401 instead of a
			// redirect, keeping its per-process startup token unreachable from a
			// LAN browser. Turn that one response into a browser-visible 302 to
			// the same gateway path with the token appended; the backend then
			// runs its own handshake (303 + Set-Cookie) and normal proxying
			// resumes. shouldBootstrap guards against loops and API false hits.
			if shouldBootstrap(resp, fc) {
				if tok, ok := bootstrapToken(fc.Bootstrap); ok {
					resp.Body.Close()
					resp.Body = http.NoBody
					resp.StatusCode = http.StatusFound
					resp.Header.Set("Location", addBootstrapParam(fc.OriginalPath, bootstrapParam(fc.Bootstrap), tok))
					resp.Header.Set("Content-Length", "0")
					resp.Header.Del("Set-Cookie")
					resp.Header.Set("Cache-Control", "no-store")
					return nil
				}
			}

			// Rewrite backend cookies for the gateway origin/prefix (drop
			// Domain, re-root Path, clear Secure over plain HTTP). Path is only
			// re-rooted for canonical /proxy/ access: a bare/root path (referer
			// or default_service routing) lives at the gateway root, so narrowing
			// Path to the proxy prefix would stop the browser sending the cookie.
			if cookies := resp.Header.Values("Set-Cookie"); len(cookies) > 0 {
				resp.Header.Del("Set-Cookie")
				proxyPath := ""
				// A vhost owns the root path, so backend cookie Paths are never
				// narrowed. In path modes only canonical /proxy/ access re-roots
				// them; bare/root-path access leaves Path untouched.
				if fc.Mode != ForwardVHost && strings.HasPrefix(fc.OriginalPath, "/proxy/") {
					proxyPath = fc.Prefix + "/"
				}
				secure := fc.Proto == "https"
				for _, c := range cookies {
					// A backend must not set a cookie in the gateway's reserved
					// namespace: on bare/root paths the backend's Path=/ cookie
					// would overwrite the gateway's session/route cookies, and on
					// a shared parent domain it allows cookie tossing. Drop these
					// in every forwarding mode, not only vhost.
					if isGatewayCookie(c) {
						continue
					}
					resp.Header.Add("Set-Cookie", RewriteSetCookie(c, proxyPath, secure))
				}
			}

			// Throttle the response body (download) to the per-service cap.
			// The defer runs after every other body rewrite below, so whatever
			// body this function ends with (streamed, buffered, injected) is
			// rate-limited exactly once.
			if svc.BWLimit > 0 && resp.Body != nil {
				defer func() {
					if retErr == nil && resp.Body != nil && resp.Request != nil {
						resp.Body = rate.NewLimitedReaderContext(resp.Body, svc.BWLimit, resp.Request.Context())
					}
				}()
			}
			// HEAD responses carry no body; injecting would advertise a
			// Content-Length the client never receives.
			if resp.Request != nil && resp.Request.Method == "HEAD" {
				return nil
			}
			// Statuses that cannot carry a body must not receive injected
			// content (it would set a Content-Length the client never gets).
			if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified {
				return nil
			}

			// Rewrite backend redirects into gateway-relative URLs so the
			// browser stays inside the proxy prefix: leading-slash absolute
			// paths get the prefix prepended, and absolute URLs pointing back
			// at the backend itself are converted to paths first (otherwise
			// the user would be kicked out of the gateway to an unreachable
			// backend address).
			if loc := resp.Header.Get("Location"); loc != "" {
				if rewritten, ok := rewriteLocation(loc, backendPath, fc, target.Host); ok {
					resp.Header.Set("Location", rewritten)
				}
			}

			// Inject <base> tag for HTML responses so that relative/absolute paths
			// in the body resolve under the proxy prefix instead of root.
			ct := resp.Header.Get("Content-Type")
			if !strings.Contains(ct, "text/html") {
				return nil
			}

			// Defense in depth: never touch a compressed body (the Rewrite hook
			// already strips Accept-Encoding, so this should not happen).
			if resp.Header.Get("Content-Encoding") != "" {
				return nil
			}

			// Skip injection for known very large HTML responses to avoid
			// buffering the entire body in memory (first-byte latency).
			if resp.ContentLength > maxInjectHTML {
				return nil
			}

			// Read with a hard cap. Chunked/unknown-length responses have
			// ContentLength == -1; without the cap an endless or slow stream
			// would be buffered without bound. If the body exceeds the cap,
			// forward the remainder untouched (no injection) instead of
			// truncating it.
			body, err := io.ReadAll(io.LimitReader(resp.Body, maxInjectHTML+1))
			if err != nil {
				resp.Body.Close()
				return err
			}
			if int64(len(body)) > maxInjectHTML {
				// Keep streaming the remainder, but preserve the upstream body's
				// Close: io.NopCloser would drop it and leak the backend
				// connection when the client aborts before EOF.
				orig := resp.Body
				resp.Body = &readCloser{Reader: io.MultiReader(bytes.NewReader(body), orig), Closer: orig}
				resp.ContentLength = -1
				resp.Header.Del("Content-Length")
				return nil
			}
			resp.Body.Close()

			// Skip the <base> tag only when the backend already supplies its own;
			// the webcompat polyfill is injected regardless (the two are
			// unrelated, and a page's own base tag does not imply it avoids
			// secure-context-only APIs on plain HTTP).
			snippet := WebCompatPolyfill
			if !bytes.Contains(bytes.ToLower(body), []byte("<base")) {
				snippet = fmt.Sprintf("<base href=\"%s\">", html.EscapeString(fc.Base)) + WebCompatPolyfill
			}
			modified := injectBaseTag(body, []byte(snippet))

			resp.Body = io.NopCloser(bytes.NewReader(modified))
			resp.ContentLength = int64(len(modified))
			resp.Header.Set("Content-Length", strconv.Itoa(len(modified)))
			return nil
		},
	}
}

// readCloser pairs a Reader with the original response body's Closer. It is
// used when a body is partially buffered and the remainder is streamed: the
// wrapper must still close the upstream body so the connection can be released
// if the client disconnects before EOF.
type readCloser struct {
	io.Reader
	io.Closer
}

// rewriteLocation converts a backend-generated redirect into a
// gateway-relative URL. Returns ok=false to leave the Location header as-is
// (external redirects, protocol-relative URLs, already-prefixed paths).
func rewriteLocation(loc, backendPath string, fc ProxyForwardContext, backendHost string) (string, bool) {
	if loc == "" || strings.HasPrefix(loc, "/proxy/") {
		return loc, false
	}

	// Absolute URL: only rewrite when it points back at the backend we
	// proxied to; anything else (SSO, external links) must pass through.
	if strings.HasPrefix(loc, "http://") || strings.HasPrefix(loc, "https://") {
		u, err := url.Parse(loc)
		if err != nil {
			return loc, false
		}
		if !sameBackendHost(u.Host, backendHost) {
			return loc, false
		}
		loc = u.EscapedPath()
		if u.RawQuery != "" {
			loc += "?" + u.RawQuery
		}
	}

	if !strings.HasPrefix(loc, "/") || strings.HasPrefix(loc, "//") {
		return loc, false
	}

	// If backend path is set, strip it from redirects before adding prefix.
	if stripped, ok := stripBackendPath(loc, backendPath); ok {
		loc = stripped
	}
	if fc.Mode == ForwardVHost || fc.Mode == ForwardAsIs {
		// The app owns this host's root (vhost) or is mounted at the gateway
		// root (default_service / Referer / route-cookie as-is forwarding).
		// Root-absolute redirects must stay at the root; prefixing them would
		// move a root-routed SPA under /proxy/ and break its client router.
		return loc, true
	}
	return fc.Prefix + loc, true
}

// stripBackendPath maps a backend-root-absolute redirect path back to the
// service-relative path. It only strips on path-segment boundaries: matching a
// raw string prefix would turn /application into lication for backend_path
// /app. A file-like backend_path (e.g. /app/index.html) also strips its
// directory so sibling resources redirect back under the service prefix.
func stripBackendPath(loc, backendPath string) (string, bool) {
	bp := strings.TrimSpace(backendPath)
	if bp == "" || bp == "/" {
		return loc, false
	}
	if !strings.HasPrefix(bp, "/") {
		bp = "/" + bp
	}

	// The backend path itself (optionally with a query) is the service root.
	if loc == bp {
		return "/", true
	}
	if strings.HasPrefix(loc, bp+"?") {
		return "/" + loc[len(bp):], true
	}

	// A file-like backend path: sub-resources live under its directory.
	if !strings.HasSuffix(bp, "/") && strings.Contains(pathpkg.Base(bp), ".") {
		dir := pathpkg.Dir(bp)
		if loc == dir {
			return "/", true
		}
		if strings.HasPrefix(loc, dir+"/") {
			return loc[len(dir):], true
		}
		return loc, false
	}

	base := strings.TrimRight(bp, "/")
	if base == "" {
		return loc, false
	}
	if loc == base {
		return "/", true
	}
	if strings.HasPrefix(loc, base+"/") || strings.HasPrefix(loc, base+"?") {
		return loc[len(base):], true
	}
	return loc, false
}

// isGatewayCookie reports whether a backend Set-Cookie uses a name in the
// gateway's reserved namespace. Such cookies are dropped in every forwarding
// mode to prevent a backend from shadowing the gateway's session/route state
// (cookie tossing), especially on bare/root paths where Path=/ is preserved.
func isGatewayCookie(raw string) bool {
	// Extract the name from the first pair without relying on the full
	// Set-Cookie parser: browsers are lenient, so a malformed gateway cookie
	// must still be dropped rather than passed through.
	pair := raw
	if i := strings.IndexByte(pair, ';'); i >= 0 {
		pair = pair[:i]
	}
	name := strings.TrimSpace(pair)
	if eq := strings.IndexByte(pair, '='); eq >= 0 {
		name = strings.TrimSpace(pair[:eq])
	}
	if name == "" {
		return false
	}
	return auth.IsGatewayCookieName(name)
}

// sameBackendHost reports whether a redirect target host refers to the same
// backend endpoint as the proxied host, tolerating localhost/127.0.0.1/::1
// spelling differences (backends often emit the loopback spelling they were
// started with).
func sameBackendHost(redirectHost, backendHost string) bool {
	if strings.EqualFold(redirectHost, backendHost) {
		return true
	}
	rh, rp := splitHostPort(redirectHost)
	bh, bp := splitHostPort(backendHost)
	if rp != bp {
		return false
	}
	loopback := map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}
	return loopback[strings.ToLower(rh)] && loopback[strings.ToLower(bh)]
}

func splitHostPort(h string) (host, port string) {
	if host, port, err := net.SplitHostPort(h); err == nil {
		return host, port
	}
	return h, ""
}

// webCompatPolyfill is a small inline script injected into proxied HTML pages
// served over plain HTTP (an insecure context). Browsers only expose
// crypto.randomUUID in secure contexts (HTTPS/localhost), so apps that call it
// — e.g. dsh's RPC layer mints a UUID per request — crash with
// "crypto.randomUUID is not a function" when reached through an HTTP gateway.
// getRandomValues is available on insecure origins, so the polyfill rebuilds
// the missing method from it. It is a no-op on HTTPS (randomUUID already
// defined) and for pages that never call it.
const WebCompatPolyfill = `<script>(function(){var c=window.crypto;if(c&&typeof c.randomUUID!=="function"&&c.getRandomValues){try{Object.defineProperty(c,"randomUUID",{value:function(){var b=c.getRandomValues(new Uint8Array(16));b[6]=b[6]&15|64;b[8]=b[8]&63|128;var h="";for(var i=0;i<16;i++){h+=(b[i]<16?"0":"")+b[i].toString(16)}return h.slice(0,8)+"-"+h.slice(8,12)+"-"+h.slice(12,16)+"-"+h.slice(16,20)+"-"+h.slice(20)},writable:true,configurable:true})}catch(e){}}})();</script>`

// indexOpeningTag finds an HTML opening tag by name (e.g. "head") without
// matching longer names such as <header> when looking for <head>.
func indexOpeningTag(lower []byte, name string) int {
	needle := []byte("<" + name)
	for off := 0; off < len(lower); {
		i := bytes.Index(lower[off:], needle)
		if i < 0 {
			return -1
		}
		i += off
		next := i + len(needle)
		if next >= len(lower) {
			return i
		}
		switch lower[next] {
		case '>', ' ', '\t', '\r', '\n', '/':
			return i
		}
		off = i + 1
	}
	return -1
}

// injectBaseTag inserts a <base> tag into an HTML body.
// Priority: right after <head> opening tag (to precede all <script>/<link>),
// then before </head>, then before <body, then after <html>, finally prepend.
func injectBaseTag(body, baseTag []byte) []byte {
	lower := bytes.ToLower(body)

	// 1. Right after <head> or <head ...> — sets base before any resources are loaded.
	if idx := indexOpeningTag(lower, "head"); idx != -1 {
		// find the '>' that closes the <head ...> opening tag
		closeIdx := idx + bytes.IndexByte(body[idx:], '>') + 1
		result := make([]byte, 0, len(body)+len(baseTag))
		result = append(result, body[:closeIdx]...)
		result = append(result, baseTag...)
		result = append(result, body[closeIdx:]...)
		return result
	}

	// 2. Before </head> (fallback)
	if idx := bytes.Index(lower, []byte("</head>")); idx != -1 {
		result := make([]byte, 0, len(body)+len(baseTag))
		result = append(result, body[:idx]...)
		result = append(result, baseTag...)
		result = append(result, body[idx:]...)
		return result
	}

	// 3. Before <body
	if idx := indexOpeningTag(lower, "body"); idx != -1 {
		result := make([]byte, 0, len(body)+len(baseTag))
		result = append(result, body[:idx]...)
		result = append(result, baseTag...)
		result = append(result, body[idx:]...)
		return result
	}

	// 4. After <html ...>
	if idx := indexOpeningTag(lower, "html"); idx != -1 {
		closeIdx := idx + bytes.IndexByte(body[idx:], '>') + 1
		result := make([]byte, 0, len(body)+len(baseTag))
		result = append(result, body[:closeIdx]...)
		result = append(result, baseTag...)
		result = append(result, body[closeIdx:]...)
		return result
	}

	// 5. Prepend
	return append(baseTag, body...)
}

// staticAssetExts are file extensions whose responses are never HTML, so they
// need no <base> injection and can keep the browser's Accept-Encoding for
// end-to-end compression. .html/.htm are deliberately absent (those ARE HTML).
var staticAssetExts = map[string]bool{
	".js": true, ".mjs": true, ".css": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true,
	".webp": true, ".avif": true, ".ico": true, ".bmp": true,
	".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
	".map": true, ".wasm": true, ".json": true, ".webmanifest": true,
	".mp4": true, ".webm": true, ".mp3": true, ".m4a": true, ".wav": true, ".ogg": true,
	".pdf": true, ".zip": true,
}

// isStaticAssetPath reports whether a proxied path points at a static asset
// rather than an HTML document. Used to decide whether the browser's
// Accept-Encoding can be passed through (compression) or must be stripped
// (<base> injection needs a decompressed HTML body).
func isStaticAssetPath(p string) bool {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	if staticAssetExts[strings.ToLower(pathpkg.Ext(p))] {
		return true
	}
	lower := strings.ToLower(p)
	for _, root := range []string{"/_next/", "/static/", "/assets/", "/favicon."} {
		if strings.Contains(lower, root) {
			return true
		}
	}
	return false
}

func joinBackendPath(backendPath, remainingPath string) string {
	backendPath = strings.TrimSpace(backendPath)
	if backendPath == "" || backendPath == "/" {
		if remainingPath == "" {
			return "/"
		}
		return remainingPath
	}
	if !strings.HasPrefix(backendPath, "/") {
		backendPath = "/" + backendPath
	}
	if remainingPath == "" || remainingPath == "/" {
		return pathpkg.Clean(backendPath)
	}

	base := backendPath
	// If backend_path points to a file (e.g. /app/index.html), sub-resources
	// should resolve under that file's directory, not under index.html/...
	if !strings.HasSuffix(backendPath, "/") && strings.Contains(pathpkg.Base(backendPath), ".") {
		base = pathpkg.Dir(backendPath)
	}
	return pathpkg.Join(base, remainingPath)
}
