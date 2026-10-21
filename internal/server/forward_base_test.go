package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seqyuan/goprox/internal/auth"
	"github.com/seqyuan/goprox/internal/config"
)

func htmlBackend(t *testing.T, gotPath *string) *httptest.Server {
	t.Helper()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*gotPath = r.URL.Path
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte("<html><head><title>x</title></head><body>ok</body></html>"))
	}))
	t.Cleanup(backend.Close)
	return backend
}

func serverWithDiamondService(t *testing.T, host, port, defaultService string) *Server {
	t.Helper()
	configDir := t.TempDir()
	cfgPath := config.UserConfigPath(configDir, "alice")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0700); err != nil {
		t.Fatal(err)
	}
	defaultLine := ""
	if defaultService != "" {
		defaultLine = "default_service: " + defaultService + "\n"
	}
	cfg := fmt.Sprintf(
		"auth:\n  password_hash: \"%s\"\n%s"+
			"services:\n  - id: diamond\n    name: Diamond\n    host: %s\n    port: %s\n    path: /diamond\n    websocket: true\n",
		strings.Repeat("1", 64), defaultLine, host, port,
	)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	return New(&config.StateConfig{
		Server: config.ServerState{Host: "127.0.0.1", Port: 30152},
		Auth:   config.AuthState{SessionSecret: "testsecret", SessionTTL: 86400},
	}, configDir)
}

func aliceSessionCookie() string {
	return auth.SetSessionCookie("testsecret", 86400, "alice", auth.SessionRev(strings.Repeat("1", 64)), false)
}

// As-is forwarding keeps the browser path, so <base> must be the directory of
// that path. This is the SvelteKit case: ../_app/... from /vault/project-db
// must resolve to /_app/..., not /proxy/<user>/_app/...
func TestBarePathHTMLBaseUsesRequestDirectory(t *testing.T) {
	var gotPath string
	backend := htmlBackend(t, &gotPath)
	host, port := backendAddr(t, backend)
	srv := serverWithDiamondService(t, host, port, "diamond")

	cases := []struct {
		path     string
		wantBase string
	}{
		{"/vault/project-db", "/vault/"},
		{"/vault/report/page.html", "/vault/report/"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			gotPath = ""
			req := httptest.NewRequest("GET", tc.path, nil)
			req.Header.Set("Cookie", aliceSessionCookie())
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
			}
			if gotPath != tc.path {
				t.Fatalf("backend saw %q, want %q", gotPath, tc.path)
			}
			body := rec.Body.String()
			if !strings.Contains(body, `<base href="`+tc.wantBase+`">`) {
				t.Fatalf("missing <base href=%q>; body=%s", tc.wantBase, body)
			}
			if strings.Contains(body, `<base href="/proxy/alice/diamond/`) {
				t.Fatalf("bare path got canonical proxy base: %s", body)
			}
		})
	}
}

// Canonical /proxy/... access must keep its existing base calculation.
func TestCanonicalProxyHTMLBaseUnchanged(t *testing.T) {
	var gotPath string
	backend := htmlBackend(t, &gotPath)
	host, port := backendAddr(t, backend)
	srv := serverWithDiamondService(t, host, port, "")

	req := httptest.NewRequest("GET", "/proxy/alice/diamond/report/page.html", nil)
	req.Header.Set("Cookie", aliceSessionCookie())
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if gotPath != "/report/page.html" {
		t.Fatalf("backend saw %q, want /report/page.html", gotPath)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `<base href="/proxy/alice/diamond/report/">`) {
		t.Fatalf("canonical base changed; body=%s", body)
	}
}
