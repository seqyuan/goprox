package server

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seqyuan/goprox/internal/auth"
	"github.com/seqyuan/goprox/internal/config"
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
	req.Header.Set("Cookie", auth.SetSessionCookie("testsecret", 86400, "alice", false))
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
		auth.SetSessionCookie("testsecret", 86400, "alice", false)+"; "+
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
