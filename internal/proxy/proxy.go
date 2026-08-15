package proxy

import (
	"bytes"
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
		if name == auth.SessionCookieName || name == auth.RouteCookieName || strings.HasPrefix(name, auth.RouteCookiePrefix) {
			continue
		}
		kept = append(kept, part)
	}
	return strings.Join(kept, "; ")
}

// ProxyForwardContext holds forwarding metadata.
type ProxyForwardContext struct {
	Prefix   string
	Base     string // <base href> to inject: directory of the served document
	ClientIP string
	Proto    string
	Host     string
}

// BuildProxyForwardContext creates forwarding context from a request and match.
func BuildProxyForwardContext(r *http.Request, username, servicePath string, legacy bool) ProxyForwardContext {
	prefix := "/proxy/" + username + servicePath
	if legacy {
		prefix = "/proxy" + servicePath
	}
	return ProxyForwardContext{
		Prefix:   prefix,
		Base:     prefix + "/",
		ClientIP: auth.ClientIP(r),
		Proto:    proto(r),
		Host:     r.Host,
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

// maxInjectHTML caps how much of an HTML body we buffer for <base>
// injection. Known-length responses larger than this are passed through
// untouched; unknown-length (chunked) responses are read up to this cap
// and the remainder streamed, so memory stays bounded either way.
// (Package-level var so tests can shrink it to exercise the cap.)
var maxInjectHTML int64 = 8 << 20

// NewReverseProxy creates a configured reverse proxy for a service.
func NewReverseProxy(svc *config.ServiceConfig, fc ProxyForwardContext) *httputil.ReverseProxy {
	target := &url.URL{
		Scheme: "http",
		Host:   svc.Host + ":" + strconv.Itoa(svc.Port),
	}

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

			// Strip gateway cookies
			if cookie := pr.In.Header.Get("Cookie"); cookie != "" {
				pr.Out.Header.Set("Cookie", stripGatewayCookie(cookie))
			}

			// Forwarded headers: send only the peer address computed by
			// ClientIP. A client-supplied X-Forwarded-For must not be passed
			// through, otherwise a backend that trusts XFF (for logging or
			// IP-based access control) would see an attacker-controlled source.
			pr.Out.Header.Set("X-Forwarded-For", fc.ClientIP)
			pr.Out.Header.Set("X-Forwarded-Proto", fc.Proto)
			pr.Out.Header.Set("X-Forwarded-Host", fc.Host)
			pr.Out.Header.Set("X-Forwarded-Prefix", fc.Prefix)
		},
		ModifyResponse: func(resp *http.Response) error {
			// HEAD responses carry no body; injecting would advertise a
			// Content-Length the client never receives.
			if resp.Request != nil && resp.Request.Method == "HEAD" {
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
				resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), resp.Body))
				resp.ContentLength = -1
				resp.Header.Del("Content-Length")
				return nil
			}
			resp.Body.Close()

			// Skip if the backend already supplies its own <base> tag.
			if bytes.Contains(bytes.ToLower(body), []byte("<base")) {
				resp.Body = io.NopCloser(bytes.NewReader(body))
				return nil
			}

			baseTag := fmt.Sprintf("<base href=\"%s\">", html.EscapeString(fc.Base))
			modified := injectBaseTag(body, []byte(baseTag))

			resp.Body = io.NopCloser(bytes.NewReader(modified))
			resp.ContentLength = int64(len(modified))
			resp.Header.Set("Content-Length", strconv.Itoa(len(modified)))
			return nil
		},
	}
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
	if backendPath != "" && strings.HasPrefix(loc, backendPath) {
		loc = strings.TrimPrefix(loc, backendPath)
		if loc == "" {
			loc = "/"
		}
	}
	return fc.Prefix + loc, true
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

// injectBaseTag inserts a <base> tag into an HTML body.
// Priority: right after <head> opening tag (to precede all <script>/<link>),
// then before </head>, then before <body, then after <html>, finally prepend.
func injectBaseTag(body, baseTag []byte) []byte {
	lower := bytes.ToLower(body)

	// 1. Right after <head> or <head ...> — sets base before any resources are loaded.
	if idx := bytes.Index(lower, []byte("<head")); idx != -1 {
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
	if idx := bytes.Index(lower, []byte("<body")); idx != -1 {
		result := make([]byte, 0, len(body)+len(baseTag))
		result = append(result, body[:idx]...)
		result = append(result, baseTag...)
		result = append(result, body[idx:]...)
		return result
	}

	// 4. After <html ...>
	if idx := bytes.Index(lower, []byte("<html")); idx != -1 {
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
