package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seqyuan/goprox/internal/config"
)

type rootAbsoluteBackend struct {
	srv  *httptest.Server
	path string
}

func newRootAbsoluteBackend(t *testing.T, marker string) *rootAbsoluteBackend {
	t.Helper()
	b := &rootAbsoluteBackend{}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.path = r.URL.Path
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<html><head></head><body>%s</body></html>", marker)
	}))
	t.Cleanup(b.srv.Close)
	return b
}

// writeRootAbsoluteUser writes a user whose first service is /service. When
// defHost is non-empty, /xifeng is added as default_service.
func writeRootAbsoluteUser(t *testing.T, configDir, username, svcHost, svcPort string, rootAbsolute bool, defHost, defPort string) {
	t.Helper()
	cfgPath := config.UserConfigPath(configDir, username)
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0700); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("auth:\n  password_hash: \"" + strings.Repeat("1", 64) + "\"\n")
	if defHost != "" {
		b.WriteString("default_service: xifeng\n")
	}
	b.WriteString("services:\n")
	b.WriteString(fmt.Sprintf(
		"  - id: service\n    name: Service\n    host: %s\n    port: %s\n    path: /service\n    root_absolute: %t\n    websocket: true\n",
		svcHost, svcPort, rootAbsolute,
	))
	if defHost != "" {
		b.WriteString(fmt.Sprintf(
			"  - id: xifeng\n    name: Xifeng\n    host: %s\n    port: %s\n    path: /xifeng\n    websocket: true\n",
			defHost, defPort,
		))
	}
	if err := os.WriteFile(cfgPath, []byte(b.String()), 0600); err != nil {
		t.Fatal(err)
	}
}

func newRootAbsoluteServer(t *testing.T, svc, def *rootAbsoluteBackend, rootAbsolute bool) *Server {
	t.Helper()
	configDir := t.TempDir()
	svcHost, svcPort := backendAddr(t, svc.srv)
	defHost, defPort := "", ""
	if def != nil {
		defHost, defPort = backendAddr(t, def.srv)
	}
	writeRootAbsoluteUser(t, configDir, "alice", svcHost, svcPort, rootAbsolute, defHost, defPort)
	return New(&config.StateConfig{
		Server: config.ServerState{Host: "127.0.0.1", Port: 30152},
		Auth:   config.AuthState{SessionSecret: "testsecret", SessionTTL: 86400},
	}, configDir)
}

func rootAbsoluteRequest(t *testing.T, srv *Server, path, cookie, referer string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("Cookie", cookie)
	if referer != "" {
		req.Header.Set("Referer", referer)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

// A root-absolute app's page link is routed back to it via the current page's
// Referer, before default_service would claim the bare path.
func TestRootAbsoluteRefererRoutesBarePage(t *testing.T) {
	svc := newRootAbsoluteBackend(t, "service")
	def := newRootAbsoluteBackend(t, "xifeng")
	srv := newRootAbsoluteServer(t, svc, def, true)

	// Both page links (/docs/) and root-absolute assets (/scss/...) must be
	// routed back to the app before default_service page/resource handling.
	for _, path := range []string{"/docs/", "/scss/main.css"} {
		t.Run(path, func(t *testing.T) {
			svc.path = ""
			def.path = ""
			rec := rootAbsoluteRequest(t, srv, path, aliceSessionCookie(), "http://gw/proxy/alice/service/")
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
			}
			if svc.path != path {
				t.Fatalf("root-absolute service saw %q, want %q", svc.path, path)
			}
			if def.path != "" {
				t.Fatalf("default service must not be hit, saw %q", def.path)
			}
			if !strings.Contains(rec.Body.String(), "service") {
				t.Fatalf("unexpected body: %s", rec.Body.String())
			}
		})
	}
}

// A reload/bookmark without a Referer still works when the route cookie points
// at the root-absolute service.
func TestRootAbsoluteRouteCookieFallback(t *testing.T) {
	svc := newRootAbsoluteBackend(t, "service")
	def := newRootAbsoluteBackend(t, "xifeng")
	srv := newRootAbsoluteServer(t, svc, def, true)

	cookie := aliceSessionCookie() + "; goprox_route=/proxy/alice/service"
	rec := rootAbsoluteRequest(t, srv, "/docs/", cookie, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if svc.path != "/docs/" {
		t.Fatalf("root-absolute service saw %q, want /docs/", svc.path)
	}
	if def.path != "" {
		t.Fatalf("default service must not be hit, saw %q", def.path)
	}
}

// Without Referer/route context, page-like bare paths keep going to
// default_service.
func TestRootAbsoluteWithoutContextFallsBackToDefault(t *testing.T) {
	svc := newRootAbsoluteBackend(t, "service")
	def := newRootAbsoluteBackend(t, "xifeng")
	srv := newRootAbsoluteServer(t, svc, def, true)

	rec := rootAbsoluteRequest(t, srv, "/docs/", aliceSessionCookie(), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if def.path != "/docs/" {
		t.Fatalf("default service saw %q, want /docs/", def.path)
	}
	if svc.path != "" {
		t.Fatalf("root-absolute service must not be hit, saw %q", svc.path)
	}
}

// The opt-in flag is per service: a Referer from a non-flagged service must
// not override default_service.
func TestRootAbsoluteNonFlaggedRefererKeepsDefault(t *testing.T) {
	svc := newRootAbsoluteBackend(t, "service")
	def := newRootAbsoluteBackend(t, "xifeng")
	srv := newRootAbsoluteServer(t, svc, def, false)

	rec := rootAbsoluteRequest(t, srv, "/docs/", aliceSessionCookie(), "http://gw/proxy/alice/service/")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if def.path != "/docs/" {
		t.Fatalf("default service saw %q, want /docs/", def.path)
	}
	if svc.path != "" {
		t.Fatalf("non-flagged service must not be hit, saw %q", svc.path)
	}
}

// A Referer naming another user's root-absolute service must not route across
// users; the request falls back to the session user's default service.
func TestRootAbsoluteRefererRejectsOtherUser(t *testing.T) {
	aliceSvc := newRootAbsoluteBackend(t, "alice-service")
	aliceDef := newRootAbsoluteBackend(t, "alice-default")
	bobSvc := newRootAbsoluteBackend(t, "bob-service")

	configDir := t.TempDir()
	ah, ap := backendAddr(t, aliceSvc.srv)
	dh, dp := backendAddr(t, aliceDef.srv)
	writeRootAbsoluteUser(t, configDir, "alice", ah, ap, true, dh, dp)
	bh, bp := backendAddr(t, bobSvc.srv)
	writeRootAbsoluteUser(t, configDir, "bob", bh, bp, true, "", "")

	srv := New(&config.StateConfig{
		Server: config.ServerState{Host: "127.0.0.1", Port: 30152},
		Auth:   config.AuthState{SessionSecret: "testsecret", SessionTTL: 86400},
	}, configDir)

	rec := rootAbsoluteRequest(t, srv, "/docs/", aliceSessionCookie(), "http://gw/proxy/bob/service/")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if aliceDef.path != "/docs/" {
		t.Fatalf("alice default service saw %q, want /docs/", aliceDef.path)
	}
	if aliceSvc.path != "" {
		t.Fatalf("alice service must not be hit, saw %q", aliceSvc.path)
	}
	if bobSvc.path != "" {
		t.Fatalf("bob service must not be hit, saw %q", bobSvc.path)
	}
}

// A canonical Referer from a non-flagged service is authoritative: a stale
// route cookie for a root-absolute service must not steal its bare path.
func TestRootAbsoluteNonFlaggedRefererIgnoresStaleRouteCookie(t *testing.T) {
	svc := newRootAbsoluteBackend(t, "service")
	def := newRootAbsoluteBackend(t, "xifeng")
	srv := newRootAbsoluteServer(t, svc, def, true)

	cookie := aliceSessionCookie() + "; goprox_route=/proxy/alice/service"
	rec := rootAbsoluteRequest(t, srv, "/docs/", cookie, "http://gw/proxy/alice/xifeng/")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if def.path != "/docs/" {
		t.Fatalf("default service saw %q, want /docs/", def.path)
	}
	if svc.path != "" {
		t.Fatalf("stale route cookie must not override the canonical Referer; service saw %q", svc.path)
	}
}

// Legacy /proxy<path>/... pages (no username segment) are also valid Referer
// sources for root-absolute routing.
func TestRootAbsoluteLegacyRefererRoutes(t *testing.T) {
	svc := newRootAbsoluteBackend(t, "service")
	def := newRootAbsoluteBackend(t, "xifeng")
	srv := newRootAbsoluteServer(t, svc, def, true)

	rec := rootAbsoluteRequest(t, srv, "/docs/", aliceSessionCookie(), "http://gw/proxy/service/")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if svc.path != "/docs/" {
		t.Fatalf("root-absolute service saw %q, want /docs/", svc.path)
	}
	if def.path != "" {
		t.Fatalf("default service must not be hit, saw %q", def.path)
	}
}
