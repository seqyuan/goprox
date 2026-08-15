package server

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seqyuan/goprox/internal/auth"
	"github.com/seqyuan/goprox/internal/config"
	"github.com/seqyuan/goprox/internal/proxy"
)

// gzipBackendSrv returns a backend that serves HTML gzipped when the client
// advertises gzip (like nginx does), recording the paths it saw.
func gzipBackendSrv(t *testing.T) (*httptest.Server, *[]string) {
	var seen []string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Path)
		html := "<html><head><title>Hi</title></head><body>hello</body></html>"
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			gz.Write([]byte(html))
			gz.Close()
			return
		}
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, html)
	}))
	t.Cleanup(backend.Close)
	return backend, &seen
}

func backendAddr(t *testing.T, backend *httptest.Server) (host, port string) {
	t.Helper()
	addr := backend.Listener.Addr().String()
	i := strings.LastIndex(addr, ":")
	return addr[:i], addr[i+1:]
}

func srvForBackend(t *testing.T, host, port string) *Server {
	t.Helper()
	configDir := t.TempDir()
	cfgPath := config.UserConfigPath(configDir, "alice")
	os.MkdirAll(filepath.Dir(cfgPath), 0700)
	cfg := fmt.Sprintf("auth:\n  password_hash: \"%s\"\nservices:\n  - id: jupyter\n    name: Jupyter\n    host: %s\n    port: %s\n    path: /jupyter\n    websocket: true\n", strings.Repeat("1", 64), host, port)
	os.WriteFile(cfgPath, []byte(cfg), 0600)
	return New(&config.StateConfig{
		Server: config.ServerState{Host: "127.0.0.1", Port: 1908},
		Auth:   config.AuthState{SessionSecret: "testsecret", SessionTTL: 86400},
	}, configDir)
}

// A gzip-compressed HTML response must not be corrupted by <base> injection:
// the client-side decompressed body must still contain the injected tag.
func TestGzipHTMLBaseInjection(t *testing.T) {
	backend, _ := gzipBackendSrv(t)
	host, port := backendAddr(t, backend)
	srv := srvForBackend(t, host, port)

	req := httptest.NewRequest("GET", "/proxy/alice/jupyter/", nil)
	req.Header.Set("Cookie", auth.SetSessionCookie("testsecret", 86400, "alice", auth.SessionRev(strings.Repeat("1", 64)), false))
	req.Header.Set("Accept-Encoding", "gzip, deflate, br") // browser behavior
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	// The proxy must not return a compressed body it cannot regenerate; the
	// Rewrite hook strips Accept-Encoding so the backend sends identity.
	if rr.Header().Get("Content-Encoding") != "" {
		// If the backend still compressed (defensive path), the body must at
		// least be valid gzip containing the base tag after decompression.
		zr, err := gzip.NewReader(bytes.NewReader(rr.Body.Bytes()))
		if err != nil {
			t.Fatalf("response body corrupted by injection: %v", err)
		}
		out, _ := io.ReadAll(zr)
		if !bytes.Contains(out, []byte(`<base href="/proxy/alice/jupyter/">`)) {
			t.Fatalf("decompressed body missing base tag: %s", out)
		}
		return
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte(`<base href="/proxy/alice/jupyter/">`)) {
		t.Fatalf("body missing base tag: %s", rr.Body.Bytes())
	}
}

// An unauthenticated request with only a stale route cookie must NOT be
// forwarded to the backend; it must be sent to the login page instead.
func TestRouteCookieWithoutSessionRedirectsToLogin(t *testing.T) {
	backend, _ := gzipBackendSrv(t)
	host, port := backendAddr(t, backend)
	srv := srvForBackend(t, host, port)

	req := httptest.NewRequest("GET", "/api/contents", nil)
	req.Header.Set("Cookie", auth.SetRouteCookie("/proxy/alice/jupyter"))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected redirect to login, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.HasPrefix(loc, "/login?next=") {
		t.Fatalf("expected /login?next= redirect, got %q", loc)
	}
}

// GET /login must show the GoProx login page even when stale route cookies
// are present (previously hijacked to the backend after logout).
func TestLoginPageNotHijackedByStaleRouteCookie(t *testing.T) {
	backend, _ := gzipBackendSrv(t)
	host, port := backendAddr(t, backend)
	srv := srvForBackend(t, host, port)

	req := httptest.NewRequest("GET", "/login?next=/proxy/alice/jupyter/", nil)
	req.Header.Set("Cookie", auth.SetRouteCookie("/proxy/alice/jupyter"))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected login page 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "GoProx") || !strings.Contains(rr.Body.String(), "登录") {
		t.Fatalf("login page not rendered: %s", rr.Body.String()[:min(200, rr.Body.Len())])
	}
}

// Logout must clear the session cookie and every route cookie, so the next
// browser user cannot reach backends without logging in.
func TestLogoutClearsRouteCookies(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/logout", nil)
	req.Header.Set("Cookie",
		auth.SetSessionCookie("testsecret", 86400, "alice", "rev", false)+"; "+
			auth.SetRouteCookie("/proxy/alice/jupyter")+"; "+
			auth.SetRouteCookie("/proxy/alice/rstudio"))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rr.Code)
	}
	var cleared int
	for _, c := range rr.Result().Header.Values("Set-Cookie") {
		if strings.Contains(c, "Expires=Thu, 01 Jan 1970") {
			cleared++
		}
	}
	if cleared < 3 {
		t.Fatalf("expected session + 2 route cookies cleared, got %d: %v", cleared, rr.Result().Header.Values("Set-Cookie"))
	}
}

// A plain HTML file served from a subdirectory must get a <base> pointing at
// that subdirectory (not the service prefix), so relative links resolve there.
func TestSubdirectoryHTMLGetsDirectoryBase(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, "<html><head></head><body><a href=\"next.html\">next</a></body></html>")
	}))
	t.Cleanup(backend.Close)
	host, port := backendAddr(t, backend)
	srv := srvForBackend(t, host, port)

	req := httptest.NewRequest("GET", "/proxy/alice/jupyter/report/page.html", nil)
	req.Header.Set("Cookie", auth.SetSessionCookie("testsecret", 86400, "alice", auth.SessionRev(strings.Repeat("1", 64)), false))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `<base href="/proxy/alice/jupyter/report/">`) {
		t.Fatalf("expected directory-scoped base tag, got body: %s", rr.Body.String())
	}
}

// Gateway-owned HTML pages must not be framed by other sites (clickjacking)
// or sniffed as a different content type.
func TestGatewayPagesSetSecurityHeaders(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if got := rr.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("expected X-Frame-Options DENY, got %q", got)
	}
	if got := rr.Header().Get("Content-Security-Policy"); got != "frame-ancestors 'none'" {
		t.Fatalf("expected CSP frame-ancestors 'none', got %q", got)
	}
	if got := rr.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("expected X-Content-Type-Options nosniff, got %q", got)
	}
}

// absoluteRedirectBackendSrv serves HTML plus a redirect to its own absolute
// URL (as backends do when they derive links from the Host header).
func absoluteRedirectBackendSrv(t *testing.T) *httptest.Server {
	t.Helper()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "http://"+r.Host+"/lab", http.StatusFound)
		default:
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, "<html><head></head><body>ok</body></html>")
		}
	}))
	t.Cleanup(backend.Close)
	return backend
}

// An absolute redirect pointing back at the backend's own host must be
// rewritten to a gateway-relative URL so the browser stays inside the proxy.
func TestAbsoluteRedirectRewrittenToGatewayPath(t *testing.T) {
	backend := absoluteRedirectBackendSrv(t)
	host, port := backendAddr(t, backend)
	srv := srvForBackend(t, host, port)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/proxy/alice/jupyter/", nil)
	req.Header.Set("Cookie", auth.SetSessionCookie("testsecret", 86400, "alice", auth.SessionRev(strings.Repeat("1", 64)), false))
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/proxy/alice/jupyter/") {
		t.Fatalf("redirect escaped the proxy prefix: %q", loc)
	}
	if strings.Contains(loc, backend.Listener.Addr().String()) {
		t.Fatalf("redirect leaked the backend address: %q", loc)
	}
}

// A chunked (unknown Content-Length) HTML response must be forwarded
// completely (no truncation, no hang) with the <base> tag still injected.
func TestChunkedHTMLForwardedWithBaseInjection(t *testing.T) {
	chunk := strings.Repeat("<p>padding</p>", 10000)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		// No Content-Length => chunked. Write in pieces to simulate streaming.
		for i := 0; i < 5; i++ {
			io.WriteString(w, chunk)
			w.(http.Flusher).Flush()
		}
	}))
	t.Cleanup(backend.Close)
	host, port := backendAddr(t, backend)
	srv := srvForBackend(t, host, port)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/proxy/alice/jupyter/", nil)
	req.Header.Set("Cookie", auth.SetSessionCookie("testsecret", 86400, "alice", auth.SessionRev(strings.Repeat("1", 64)), false))
	srv.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()
	wantLen := len(chunk)*5 + len(`<base href="/proxy/alice/jupyter/">`) + len(proxy.WebCompatPolyfill)
	if len(body) != wantLen {
		t.Fatalf("chunked body wrong size: got %d bytes, want %d", len(body), wantLen)
	}
	if !strings.HasPrefix(body, `<base href="/proxy/alice/jupyter/">`) {
		t.Fatalf("base tag not injected at start of chunked body")
	}
	if !strings.Contains(body, proxy.WebCompatPolyfill) {
		t.Fatalf("webcompat polyfill missing from chunked body")
	}
	if !strings.HasSuffix(body, "</p>") {
		t.Fatalf("chunked body truncated at the end")
	}
}

// A bare gateway path that matches no service and no route cookie is forwarded
// to the user's configured default service (DefaultService), letting root-based
// SPAs serve at the gateway root without app-side basePath changes.
func TestDefaultServiceForwardsBarePath(t *testing.T) {
	var gotPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><head></head><body>spa</body></html>"))
	}))
	defer backend.Close()
	host, port := backendAddr(t, backend)

	configDir := t.TempDir()
	cfgPath := config.UserConfigPath(configDir, "alice")
	os.MkdirAll(filepath.Dir(cfgPath), 0700)
	cfg := fmt.Sprintf("auth:\n  password_hash: \"%s\"\ndefault_service: xifeng\nservices:\n  - id: xifeng\n    name: Xifeng\n    host: %s\n    port: %s\n    path: /xifeng\n    websocket: true\n", strings.Repeat("1", 64), host, port)
	os.WriteFile(cfgPath, []byte(cfg), 0600)
	srv := New(&config.StateConfig{
		Server: config.ServerState{Host: "127.0.0.1", Port: 1908},
		Auth:   config.AuthState{SessionSecret: "testsecret", SessionTTL: 86400},
	}, configDir)

	// A bare path /dashboard (not a service path) with a valid session and no
	// route cookie must be forwarded to the default service as-is.
	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.Header.Set("Cookie", auth.SetSessionCookie("testsecret", 86400, "alice", auth.SessionRev(strings.Repeat("1", 64)), false))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if gotPath != "/dashboard" {
		t.Fatalf("backend saw %q, want /dashboard", gotPath)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	// The route cookies must be stamped so sub-resources stay on the service.
	if !strings.Contains(rec.Header().Get("Set-Cookie"), "goprox_route") {
		t.Fatalf("missing route cookie in response: %v", rec.Header().Get("Set-Cookie"))
	}
}

// Without a valid session the default service must never be reached (route
// cookies / default forwarding are not credentials).
func TestDefaultServiceRequiresSession(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("backend must not be reached without a session")
	}))
	defer backend.Close()
	host, port := backendAddr(t, backend)

	configDir := t.TempDir()
	cfgPath := config.UserConfigPath(configDir, "alice")
	os.MkdirAll(filepath.Dir(cfgPath), 0700)
	cfg := fmt.Sprintf("auth:\n  password_hash: \"%s\"\ndefault_service: xifeng\nservices:\n  - id: xifeng\n    name: Xifeng\n    host: %s\n    port: %s\n    path: /xifeng\n    websocket: true\n", strings.Repeat("1", 64), host, port)
	os.WriteFile(cfgPath, []byte(cfg), 0600)
	srv := New(&config.StateConfig{
		Server: config.ServerState{Host: "127.0.0.1", Port: 1908},
		Auth:   config.AuthState{SessionSecret: "testsecret", SessionTTL: 86400},
	}, configDir)

	req := httptest.NewRequest("GET", "/dashboard", nil) // no cookie
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (no session must not reach backend)", rec.Code)
	}
}

// A page-like bare path goes to the default service deterministically even
// when a route cookie points at another service; a resource-like path
// (/api/...) follows its Referer instead, so the SPA's API calls stick to the
// page that issued them.
func TestDefaultServicePageVsResourceRouting(t *testing.T) {
	var gotPath, gotHost string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotHost = r.Host
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("ok"))
	}))
	defer backend.Close()
	host, port := backendAddr(t, backend)
	backendHost := net.JoinHostPort(host, port)

	configDir := t.TempDir()
	cfgPath := config.UserConfigPath(configDir, "alice")
	os.MkdirAll(filepath.Dir(cfgPath), 0700)
	cfg := fmt.Sprintf("auth:\n  password_hash: \"%s\"\ndefault_service: xifeng\nservices:\n  - id: xifeng\n    name: Xifeng\n    host: %s\n    port: %s\n    path: /xifeng\n    websocket: true\n", strings.Repeat("1", 64), host, port)
	os.WriteFile(cfgPath, []byte(cfg), 0600)
	srv := New(&config.StateConfig{
		Server: config.ServerState{Host: "127.0.0.1", Port: 1908},
		Auth:   config.AuthState{SessionSecret: "testsecret", SessionTTL: 86400},
	}, configDir)

	sessionCookie := auth.SetSessionCookie("testsecret", 86400, "alice", auth.SessionRev(strings.Repeat("1", 64)), false)

	// 1. Page-like /dashboard with a route cookie pointing at a DIFFERENT
	// service prefix still goes to the default service.
	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.Header.Set("Cookie", sessionCookie+"; goprox_route=/proxy/alice/other")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if gotPath != "/dashboard" {
		t.Fatalf("page path routed to %q, want /dashboard (default service)", gotPath)
	}

	// 2. Resource-like /api/x with a Referer on the default service goes there.
	req = httptest.NewRequest("GET", "/api/x", nil)
	req.Header.Set("Cookie", sessionCookie)
	req.Header.Set("Referer", "http://gateway/dashboard")
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if gotPath != "/api/x" || gotHost != backendHost {
		t.Fatalf("resource path routed to %q @ %q, want /api/x @ %s (via Referer)", gotPath, gotHost, backendHost)
	}
}
