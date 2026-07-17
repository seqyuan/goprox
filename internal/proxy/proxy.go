package proxy

import (
	"bytes"
	"fmt"
	"io"
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
		ClientIP: auth.ClientIP(r),
		Proto:    proto(r),
		Host:     r.Host,
	}
}

func proto(r *http.Request) string {
	if auth.IsSecureRequest(r) {
		return "https"
	}
	return "http"
}

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

			// Strip gateway cookies
			if cookie := pr.In.Header.Get("Cookie"); cookie != "" {
				pr.Out.Header.Set("Cookie", stripGatewayCookie(cookie))
			}

			// Set forwarded headers
			xForwardedFor := fc.ClientIP
			if prior := pr.In.Header.Get("X-Forwarded-For"); prior != "" {
				xForwardedFor = prior + ", " + fc.ClientIP
			}
			pr.Out.Header.Set("X-Forwarded-For", xForwardedFor)
			pr.Out.Header.Set("X-Forwarded-Proto", fc.Proto)
			pr.Out.Header.Set("X-Forwarded-Host", fc.Host)
			pr.Out.Header.Set("X-Forwarded-Prefix", fc.Prefix)
		},
		ModifyResponse: func(resp *http.Response) error {
			// Rewrite redirect locations
			loc := resp.Header.Get("Location")
			if loc != "" && strings.HasPrefix(loc, "/") && !strings.HasPrefix(loc, "//") && !strings.HasPrefix(loc, "/proxy/") {
				// If backend path is set, strip it from redirects before adding prefix
				if backendPath != "" && strings.HasPrefix(loc, backendPath) {
					loc = strings.TrimPrefix(loc, backendPath)
					if loc == "" {
						loc = "/"
					}
				}
				resp.Header.Set("Location", fc.Prefix+loc)
			}

			// Inject <base> tag for HTML responses so that relative/absolute paths
			// in the body resolve under the proxy prefix instead of root.
			ct := resp.Header.Get("Content-Type")
			if !strings.Contains(ct, "text/html") {
				return nil
			}

			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return err
			}

			// Skip if the backend already supplies its own <base> tag.
			if bytes.Contains(bytes.ToLower(body), []byte("<base")) {
				resp.Body = io.NopCloser(bytes.NewReader(body))
				return nil
			}

			baseTag := fmt.Sprintf("<base href=\"%s/\">", fc.Prefix)
			modified := injectBaseTag(body, []byte(baseTag))

			resp.Body = io.NopCloser(bytes.NewReader(modified))
			resp.ContentLength = int64(len(modified))
			resp.Header.Set("Content-Length", strconv.Itoa(len(modified)))
			return nil
		},
	}
}

// injectBaseTag inserts a <base> tag into an HTML body.
// It tries </head>, then <body, then <html>, falling back to prepending.
func injectBaseTag(body, baseTag []byte) []byte {
	lower := bytes.ToLower(body)

	if idx := bytes.Index(lower, []byte("</head>")); idx != -1 {
		result := make([]byte, 0, len(body)+len(baseTag))
		result = append(result, body[:idx]...)
		result = append(result, baseTag...)
		result = append(result, body[idx:]...)
		return result
	}

	if idx := bytes.Index(lower, []byte("<body")); idx != -1 {
		result := make([]byte, 0, len(body)+len(baseTag))
		result = append(result, body[:idx]...)
		result = append(result, baseTag...)
		result = append(result, body[idx:]...)
		return result
	}

	if idx := bytes.Index(lower, []byte("<html")); idx != -1 {
		closeIdx := idx + bytes.IndexByte(body[idx:], '>') + 1
		result := make([]byte, 0, len(body)+len(baseTag))
		result = append(result, body[:closeIdx]...)
		result = append(result, baseTag...)
		result = append(result, body[closeIdx:]...)
		return result
	}

	return append(baseTag, body...)
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
