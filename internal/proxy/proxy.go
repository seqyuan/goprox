package proxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"

	"github.com/seqyuan/goprox/internal/auth"
	"github.com/seqyuan/goprox/internal/config"
)

// hop-by-hop headers that should not be forwarded
var hopByHopHeaders = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailers":            true,
	"transfer-encoding":   true,
	"upgrade":             true,
	"proxy-connection":    true,
}

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
		if name == auth.SessionCookieName || name == auth.RouteCookieName {
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

	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = target.Host

			// Strip gateway cookies
			if cookie := pr.In.Header.Get("Cookie"); cookie != "" {
				pr.Out.Header.Set("Cookie", stripGatewayCookie(cookie))
			}

			// Remove hop-by-hop headers
			for key := range pr.In.Header {
				if hopByHopHeaders[strings.ToLower(key)] {
					pr.Out.Header.Del(key)
				}
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
				resp.Header.Set("Location", fc.Prefix+loc)
			}

			// Add route cookie to Set-Cookie
			routeCookie := auth.SetRouteCookie(fc.Prefix)
			resp.Header.Add("Set-Cookie", routeCookie)

			return nil
		},
	}
}

