package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seqyuan/goprox/internal/auth"
	"github.com/seqyuan/goprox/internal/config"
)

func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	configDir := t.TempDir()
	cfgPath := config.UserConfigPath(configDir, "alice")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0700); err != nil {
		t.Fatal(err)
	}
	cfg := "auth:\n  password_hash: \"" + strings.Repeat("1", 64) + "\"\nservices: []\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	reg := config.NewUserRegistry(configDir)
	reg.Reload()
	return NewHandler(reg, "testsecret")
}

func apiPost(t *testing.T, h *Handler, url, body, origin string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", auth.SetSessionCookie("testsecret", 86400, "alice", auth.SessionRev(strings.Repeat("1", 64)), false))
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	// The gateway the browser is talking to is gw:1908; callers pass an
	// Origin that either matches it (same-origin) or not (CSRF attempt).
	req.Host = "gw:1908"
	rr := httptest.NewRecorder()
	if !h.ServeHTTP(rr, req) {
		t.Fatalf("ServeHTTP did not claim request %s", url)
	}
	return rr
}

// A cross-site page must not be able to modify the user's config (CSRF).
func TestAddServiceRejectsCrossOrigin(t *testing.T) {
	h := newTestHandler(t)
	rr := apiPost(t, h, "/api/services", `{"name":"x","port":8080}`, "http://evil.example")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-origin add, got %d body=%s", rr.Code, rr.Body.String())
	}
}

// Sandboxed origins (Origin: null) must be rejected too.
func TestAddServiceRejectsNullOrigin(t *testing.T) {
	h := newTestHandler(t)
	rr := apiPost(t, h, "/api/services", `{"name":"x","port":8080}`, "null")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for null origin, got %d", rr.Code)
	}
}

// Same-origin and non-browser (no Origin) adds must still work.
func TestAddServiceSameOriginAllowed(t *testing.T) {
	h := newTestHandler(t)
	rr := apiPost(t, h, "/api/services", `{"name":"x","port":8080}`, "http://gw:1908")
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201 for same-origin add, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestAddServiceNoOriginAllowed(t *testing.T) {
	h := newTestHandler(t)
	rr := apiPost(t, h, "/api/services", `{"name":"x","port":8080}`, "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201 for no-origin add, got %d body=%s", rr.Code, rr.Body.String())
	}
}

// DELETE is state-changing too and must be origin-guarded.
func TestDeleteServiceRejectsCrossOrigin(t *testing.T) {
	h := newTestHandler(t)
	// Create one service first via the same-origin path.
	rr := apiPost(t, h, "/api/services", `{"name":"x","port":8080}`, "http://gw:1908")
	if rr.Code != http.StatusCreated {
		t.Fatalf("setup add failed: %d", rr.Code)
	}
	req := httptest.NewRequest("DELETE", "/api/services/x", nil)
	req.Header.Set("Cookie", auth.SetSessionCookie("testsecret", 86400, "alice", auth.SessionRev(strings.Repeat("1", 64)), false))
	req.Header.Set("Origin", "http://evil.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-origin delete, got %d", rec.Code)
	}
}

// Empty and oversized names must be rejected so a stray request cannot create
// nonsense cards or bloat the dashboard page.
func TestAddServiceRejectsEmptyName(t *testing.T) {
	h := newTestHandler(t)
	rr := apiPost(t, h, "/api/services", `{"name":"   ","port":8080}`, "http://gw:1908")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty name, got %d", rr.Code)
	}
}

func TestAddServiceRejectsOversizedName(t *testing.T) {
	h := newTestHandler(t)
	long := strings.Repeat("a", 201)
	rr := apiPost(t, h, "/api/services", `{"name":"`+long+`","port":8080}`, "http://gw:1908")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized name, got %d", rr.Code)
	}
}

// Oversized request bodies must be rejected with 413, not silently truncated.
func TestAddServiceRejectsOversizedBody(t *testing.T) {
	h := newTestHandler(t)
	big := `{"name":"x","port":8080,"description":"` + strings.Repeat("a", 70000) + `"}`
	rr := apiPost(t, h, "/api/services", big, "http://gw:1908")
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for oversized body, got %d", rr.Code)
	}
}

// Updating only description/category must still enforce their length bounds.
func TestUpdateServiceRejectsOversizedDescriptionWithoutName(t *testing.T) {
	h := newTestHandler(t)
	rr := apiPost(t, h, "/api/services", `{"name":"x","port":8080}`, "http://gw:1908")
	if rr.Code != http.StatusCreated {
		t.Fatalf("setup add failed: %d", rr.Code)
	}

	body := `{"description":"` + strings.Repeat("b", 501) + `"}`
	req := httptest.NewRequest("PUT", "/api/services/x", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", auth.SetSessionCookie("testsecret", 86400, "alice", auth.SessionRev(strings.Repeat("1", 64)), false))
	req.Header.Set("Origin", "http://gw:1908")
	req.Host = "gw:1908"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized description, got %d body=%s", rec.Code, rec.Body.String())
	}
}
