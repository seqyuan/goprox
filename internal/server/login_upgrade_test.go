package server

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seqyuan/goprox/internal/config"
)

func legacyHash(password string) string {
	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:])
}

func writeLegacyUser(t *testing.T, configDir, username, password string, totp bool) string {
	t.Helper()
	cfgPath := config.UserConfigPath(configDir, username)
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0700); err != nil {
		t.Fatal(err)
	}
	cfg := "auth:\n  password_hash: \"" + legacyHash(password) + "\"\n"
	if totp {
		cfg += "  totp_secret: \"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\"\n"
	}
	cfg += "services: []\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

func loginPost(t *testing.T, srv *Server, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"username": {username}, "password": {password}, "next": {"/"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "gw"
	req.Header.Set("Origin", "http://gw")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

// A successful login with a pre-bcrypt hash must rewrite it to bcrypt, and the
// session issued in the same response must be valid (its revision comes from
// the upgraded hash).
func TestLoginUpgradesLegacyHash(t *testing.T) {
	configDir := t.TempDir()
	cfgPath := writeLegacyUser(t, configDir, "alice", "s3cret", false)
	srv := New(&config.StateConfig{
		Server: config.ServerState{Host: "127.0.0.1", Port: 30152},
		Auth:   config.AuthState{SessionSecret: "testsecret", SessionTTL: 86400},
	}, configDir)

	rec := loginPost(t, srv, "alice", "s3cret")
	if rec.Code != http.StatusFound {
		t.Fatalf("login status = %d, body=%s", rec.Code, rec.Body.String())
	}

	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "password_hash: $2") {
		t.Fatalf("hash not upgraded to bcrypt:\n%s", raw)
	}
	if strings.Contains(string(raw), legacyHash("s3cret")) {
		t.Fatalf("legacy hash still present:\n%s", raw)
	}

	// The cookie issued during the upgrade must satisfy a protected request.
	cookie := ""
	for _, c := range rec.Result().Cookies() {
		if c.Name == "goprox_session" {
			cookie = c.Name + "=" + c.Value
		}
	}
	if cookie == "" {
		t.Fatal("no session cookie issued")
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "gw"
	req.Header.Set("Cookie", cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "alice") {
		t.Fatalf("upgraded session rejected: status=%d", rr.Code)
	}

	// And the new bcrypt hash still verifies the same password on a restart.
	srv2 := New(&config.StateConfig{
		Server: config.ServerState{Host: "127.0.0.1", Port: 30152},
		Auth:   config.AuthState{SessionSecret: "testsecret", SessionTTL: 86400},
	}, configDir)
	if rec := loginPost(t, srv2, "alice", "s3cret"); rec.Code != http.StatusFound {
		t.Fatalf("re-login after upgrade: %d", rec.Code)
	}
}

// The 2FA branch issues a pending token whose revision must also be the new one.
func TestLoginUpgradeKeepsTwoFAFlowWorking(t *testing.T) {
	configDir := t.TempDir()
	writeLegacyUser(t, configDir, "alice", "s3cret", true)
	srv := New(&config.StateConfig{
		Server: config.ServerState{Host: "127.0.0.1", Port: 30152},
		Auth:   config.AuthState{SessionSecret: "testsecret", SessionTTL: 86400},
	}, configDir)

	rec := loginPost(t, srv, "alice", "s3cret")
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "/login/2fa?next=") {
		t.Fatalf("2FA redirect expected, got %d %q", rec.Code, rec.Header().Get("Location"))
	}
	var pending string
	for _, c := range rec.Result().Cookies() {
		if c.Name == "goprox_2fa" {
			pending = c.Value
		}
	}
	if pending == "" {
		t.Fatal("no pending 2FA cookie")
	}
	if _, ok := srv.pendingTwoFAUser("goprox_2fa=" + pending); !ok {
		t.Fatal("pending token does not validate against the upgraded revision")
	}
}

// A read-only config must not block the login: the upgrade is best-effort.
func TestLoginUpgradeFailureDoesNotBlock(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write read-only files")
	}
	configDir := t.TempDir()
	writeLegacyUser(t, configDir, "alice", "s3cret", false)
	// Config writes go through temp-file + rename, so the *directory* is what
	// must be read-only for the upgrade to fail.
	usersDir := filepath.Dir(config.UserConfigPath(configDir, "alice"))
	if err := os.Chmod(usersDir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(usersDir, 0700) })
	srv := New(&config.StateConfig{
		Server: config.ServerState{Host: "127.0.0.1", Port: 30152},
		Auth:   config.AuthState{SessionSecret: "testsecret", SessionTTL: 86400},
	}, configDir)

	if rec := loginPost(t, srv, "alice", "s3cret"); rec.Code != http.StatusFound {
		t.Fatalf("login failed on read-only config: %d", rec.Code)
	}
}
