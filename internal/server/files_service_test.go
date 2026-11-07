package server

import (
	"archive/zip"
	"bytes"
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

// filesUser writes a user whose single service is a read-only directory
// browser over root. hostnames are optional (vhost mode).
func filesUser(t *testing.T, configDir, root string, hostnames ...string) {
	t.Helper()
	cfgPath := config.UserConfigPath(configDir, "alice")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0700); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "auth:\n  password_hash: %q\n", strings.Repeat("1", 64))
	b.WriteString("services:\n")
	b.WriteString("  - id: data\n    name: 数据盘\n    kind: files\n    path: /data\n")
	fmt.Fprintf(&b, "    root: %s\n", root)
	if len(hostnames) > 0 {
		b.WriteString("    hostnames:\n")
		for _, h := range hostnames {
			fmt.Fprintf(&b, "      - %s\n", h)
		}
	}
	if err := os.WriteFile(cfgPath, []byte(b.String()), 0600); err != nil {
		t.Fatal(err)
	}
}

func writeFiles(t *testing.T, root string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "b.txt"), []byte("deep"), 0644); err != nil {
		t.Fatal(err)
	}
}

func plainServer(t *testing.T, configDir string) *Server {
	t.Helper()
	return New(&config.StateConfig{
		Server: config.ServerState{Host: "127.0.0.1", Port: 30152},
		Auth:   config.AuthState{SessionSecret: "testsecret", SessionTTL: 86400},
	}, configDir)
}

func servingFilesGet(t *testing.T, srv *Server, path, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Host = "gw"
	req.Header.Set("Cookie", cookie)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func TestFilesServicePrefixMode(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root)
	configDir := t.TempDir()
	filesUser(t, configDir, root)
	srv := plainServer(t, configDir)
	cookie := aliceSessionCookie()

	rec := servingFilesGet(t, srv, "/proxy/alice/data/", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("listing status = %d, body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"a.txt", "sub/", `href="/proxy/alice/data/sub/"`, `href="/proxy/alice/data/?zip=1"`} {
		if !strings.Contains(body, want) {
			t.Errorf("listing missing %q", want)
		}
	}

	rec = servingFilesGet(t, srv, "/proxy/alice/data/a.txt", cookie)
	if rec.Code != http.StatusOK || rec.Body.String() != "hello" {
		t.Fatalf("file: status=%d body=%q", rec.Code, rec.Body.String())
	}

	// Zip of the whole service root.
	rec = servingFilesGet(t, srv, "/proxy/alice/data/?zip=1", cookie)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/zip" {
		t.Fatalf("zip: status=%d type=%q", rec.Code, rec.Header().Get("Content-Type"))
	}
	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatalf("zip: %v", err)
	}
	names := map[string]bool{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(rc)
		rc.Close()
		names[f.Name] = true
		if f.Name == "sub/b.txt" && string(data) != "deep" {
			t.Errorf("sub/b.txt = %q", data)
		}
	}
	if !names["a.txt"] || !names["sub/b.txt"] {
		t.Fatalf("zip entries = %v", names)
	}
}

func TestFilesServiceIsReadOnly(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root)
	configDir := t.TempDir()
	filesUser(t, configDir, root)
	srv := plainServer(t, configDir)

	for _, method := range []string{"POST", "PUT", "DELETE"} {
		req := httptest.NewRequest(method, "/proxy/alice/data/a.txt", strings.NewReader("x"))
		req.Host = "gw"
		req.Header.Set("Cookie", aliceSessionCookie())
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s status = %d, want 405", method, rec.Code)
		}
	}
	// The write attempts must not have created anything.
	if _, err := os.Stat(filepath.Join(root, "a.txt")); err != nil {
		t.Fatalf("file disappeared: %v", err)
	}
}

func TestFilesServiceHidesOtherUsersAndRequiresLogin(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root)
	configDir := t.TempDir()
	filesUser(t, configDir, root)
	srv := plainServer(t, configDir)

	// Unauthenticated: login redirect, not a listing.
	rec := servingFilesGet(t, srv, "/proxy/alice/data/", "")
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "/login?next=") {
		t.Fatalf("anon: status=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}

	// Another user's session must not see the directory (404, not 403). bob
	// needs a real config so his session revision matches the token.
	writeBobConfig(t, configDir)
	bob := auth.SetSessionCookie("testsecret", 86400, "bob", auth.SessionRev(strings.Repeat("1", 64)), false)
	rec = servingFilesGet(t, srv, "/proxy/alice/data/", bob)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-user status = %d, want 404", rec.Code)
	}
}

func TestFilesServiceVHostMode(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root)
	configDir := t.TempDir()
	filesUser(t, configDir, root, "data.example.test")
	srv := newVHostServer(t, configDir)

	req := httptest.NewRequest("GET", "/sub/", nil)
	req.Host = "data.example.test"
	req.Header.Set("Cookie", aliceSessionCookie())
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	// A vhost owns the host root: links must not grow a /proxy prefix.
	if !strings.Contains(body, `href="/sub/b.txt"`) || !strings.Contains(body, `href="/"`) {
		t.Fatalf("vhost listing links wrong:\n%s", body)
	}
	if strings.Contains(body, "/proxy/") {
		t.Fatalf("vhost listing must not emit /proxy links:\n%s", body)
	}
}

// A bare request routed by the route cookie (as-is forwarding) is served from
// the directory root and keeps bare links, so the browser stays at the gateway
// root rather than being pulled under /proxy/.
func TestFilesServiceBarePathMapsToRoot(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root)
	configDir := t.TempDir()
	filesUser(t, configDir, root)
	srv := plainServer(t, configDir)
	cookie := aliceSessionCookie() + "; goprox_route=/proxy/alice/data"

	rec := servingFilesGet(t, srv, "/sub/", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `href="/sub/b.txt"`) {
		t.Fatalf("bare listing links wrong:\n%s", body)
	}
	if strings.Contains(body, "/proxy/") {
		t.Fatalf("bare listing must not emit /proxy links:\n%s", body)
	}

	// The service path itself stays the canonical /proxy doorway.
	rec = servingFilesGet(t, srv, "/data/sub/", cookie)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/proxy/alice/data/sub/" {
		t.Fatalf("service path: status=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}
}

func writeBobConfig(t *testing.T, configDir string) {
	t.Helper()
	cfgPath := config.UserConfigPath(configDir, "bob")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0700); err != nil {
		t.Fatal(err)
	}
	cfg := fmt.Sprintf("auth:\n  password_hash: %q\nservices: []\n", strings.Repeat("1", 64))
	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
}

// server.files_roots must be enforced before the registry accepts a card: a
// service pointing outside the allowlist is dropped at load, one inside stays.
func TestFilesServiceRespectsAllowlist(t *testing.T) {
	base := t.TempDir()
	allowed := filepath.Join(base, "shared")
	outside := filepath.Join(base, "private")
	for _, dir := range []string{allowed, outside} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	configDir := filepath.Join(base, "config")
	filesUser(t, configDir, outside) // card outside the allowlist
	srv := New(&config.StateConfig{
		Server: config.ServerState{Host: "127.0.0.1", Port: 30152, FilesRoots: []string{allowed}},
		Auth:   config.AuthState{SessionSecret: "testsecret", SessionTTL: 86400},
	}, configDir)
	if n := srv.ServiceCount(); n != 0 {
		t.Fatalf("service outside files_roots was loaded (count=%d)", n)
	}

	// Same card, now inside the allowlist.
	filesUser(t, configDir, filepath.Join(allowed, "data"))
	if err := os.MkdirAll(filepath.Join(allowed, "data"), 0700); err != nil {
		t.Fatal(err)
	}
	srv = New(&config.StateConfig{
		Server: config.ServerState{Host: "127.0.0.1", Port: 30152, FilesRoots: []string{allowed}},
		Auth:   config.AuthState{SessionSecret: "testsecret", SessionTTL: 86400},
	}, configDir)
	if n := srv.ServiceCount(); n != 1 {
		t.Fatalf("service inside files_roots not loaded (count=%d)", n)
	}
	t.Cleanup(func() { config.SetFilesRootAllowlist(nil) })
}
