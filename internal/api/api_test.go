package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/seqyuan/goprox/internal/auth"
	"github.com/seqyuan/goprox/internal/config"
)

func newTestHandler(t *testing.T, ttl ...int) *Handler {
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
	sessionTTL := 86400
	if len(ttl) > 0 {
		sessionTTL = ttl[0]
	}
	return NewHandler(reg, "testsecret", sessionTTL, "", "")
}

func newVHostTestHandler(t *testing.T) (*Handler, string) {
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
	return NewHandler(reg, "testsecret", 86400, ".example.test", "gw.example.test"), configDir
}

func apiPut(t *testing.T, h *Handler, url, body, origin string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("PUT", url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", auth.SetSessionCookie("testsecret", 86400, "alice", auth.SessionRev(strings.Repeat("1", 64)), false))
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	req.Host = "gw:30152"
	rr := httptest.NewRecorder()
	if !h.ServeHTTP(rr, req) {
		t.Fatalf("ServeHTTP did not claim request %s", url)
	}
	return rr
}

func apiPost(t *testing.T, h *Handler, url, body, origin string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", auth.SetSessionCookie("testsecret", 86400, "alice", auth.SessionRev(strings.Repeat("1", 64)), false))
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	// The gateway the browser is talking to is gw:30152; callers pass an
	// Origin that either matches it (same-origin) or not (CSRF attempt).
	req.Host = "gw:30152"
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
	rr := apiPost(t, h, "/api/services", `{"name":"x","port":8080}`, "http://gw:30152")
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
	rr := apiPost(t, h, "/api/services", `{"name":"x","port":8080}`, "http://gw:30152")
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
	rr := apiPost(t, h, "/api/services", `{"name":"   ","port":8080}`, "http://gw:30152")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty name, got %d", rr.Code)
	}
}

func TestAddServiceRejectsOversizedName(t *testing.T) {
	h := newTestHandler(t)
	long := strings.Repeat("a", 201)
	rr := apiPost(t, h, "/api/services", `{"name":"`+long+`","port":8080}`, "http://gw:30152")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized name, got %d", rr.Code)
	}
}

// Oversized request bodies must be rejected with 413, not silently truncated.
func TestAddServiceRejectsOversizedBody(t *testing.T) {
	h := newTestHandler(t)
	big := `{"name":"x","port":8080,"description":"` + strings.Repeat("a", 70000) + `"}`
	rr := apiPost(t, h, "/api/services", big, "http://gw:30152")
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for oversized body, got %d", rr.Code)
	}
}

// Updating only description/category must still enforce their length bounds.
func TestUpdateServiceRejectsOversizedDescriptionWithoutName(t *testing.T) {
	h := newTestHandler(t)
	rr := apiPost(t, h, "/api/services", `{"name":"x","port":8080}`, "http://gw:30152")
	if rr.Code != http.StatusCreated {
		t.Fatalf("setup add failed: %d", rr.Code)
	}

	body := `{"description":"` + strings.Repeat("b", 501) + `"}`
	req := httptest.NewRequest("PUT", "/api/services/x", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", auth.SetSessionCookie("testsecret", 86400, "alice", auth.SessionRev(strings.Repeat("1", 64)), false))
	req.Header.Set("Origin", "http://gw:30152")
	req.Host = "gw:30152"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized description, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func apiGetWithToken(t *testing.T, h *Handler, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", "/api/services", nil)
	if token != "" {
		req.Header.Set("Cookie", auth.SessionCookieName+"="+token)
	}
	req.Host = "gw:30152"
	rr := httptest.NewRecorder()
	if !h.ServeHTTP(rr, req) {
		t.Fatalf("ServeHTTP did not claim request %s", req.URL.Path)
	}
	return rr
}

func sessionCookieFromResponse(rr *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rr.Result().Cookies() {
		if c.Name == auth.SessionCookieName {
			return c
		}
	}
	return nil
}

// An expired session must be rejected before any refresh is attempted.
func TestAPIExpiredSessionReturns401WithoutRefresh(t *testing.T) {
	h := newTestHandler(t)
	rev := auth.SessionRev(strings.Repeat("1", 64))
	token := auth.CreateSessionToken("alice", "testsecret", -1, rev)

	rr := apiGetWithToken(t, h, token)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d body=%s", rr.Code, rr.Body.String())
	}
	if c := sessionCookieFromResponse(rr); c != nil {
		t.Fatalf("expired session must not be refreshed, got Set-Cookie %q", c.String())
	}
}

// A session in the last 25% of its TTL is renewed by API activity, matching
// the dashboard/proxy sliding-session policy.
func TestAPIRefreshesSessionNearExpiry(t *testing.T) {
	h := newTestHandler(t, 60)
	rev := auth.SessionRev(strings.Repeat("1", 64))
	token := auth.CreateSessionToken("alice", "testsecret", 10, rev)
	_, oldExpiry, _, err := auth.SessionTokenParts(token)
	if err != nil {
		t.Fatal(err)
	}

	rr := apiGetWithToken(t, h, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	cookie := sessionCookieFromResponse(rr)
	if cookie == nil {
		t.Fatalf("expected a refreshed session cookie, headers=%v", rr.Result().Header.Values("Set-Cookie"))
	}
	refreshed := auth.ValidateSessionToken(cookie.Value, "testsecret", rev)
	if !refreshed.Valid || refreshed.UserID != "alice" {
		t.Fatalf("refreshed token is invalid: %+v", refreshed)
	}
	if refreshed.ExpiresAt <= oldExpiry {
		t.Fatalf("refreshed expiry %d is not later than old expiry %d", refreshed.ExpiresAt, oldExpiry)
	}
}

// Outside the refresh window the API must not emit a new cookie on every call.
func TestAPIDoesNotRefreshOutsideWindow(t *testing.T) {
	h := newTestHandler(t, 60)
	rev := auth.SessionRev(strings.Repeat("1", 64))
	token := auth.CreateSessionToken("alice", "testsecret", 30, rev)

	rr := apiGetWithToken(t, h, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if c := sessionCookieFromResponse(rr); c != nil {
		t.Fatalf("session outside the refresh window must not be refreshed, got %q", c.String())
	}
}

// A password change bumps the revision; the old token must stay invalid and
// must not be rescued by the refresh path.
func TestAPIStaleRevReturns401WithoutRefresh(t *testing.T) {
	h := newTestHandler(t, 60)
	token := auth.CreateSessionToken("alice", "testsecret", 10, "stale-revision")

	rr := apiGetWithToken(t, h, token)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d body=%s", rr.Code, rr.Body.String())
	}
	if c := sessionCookieFromResponse(rr); c != nil {
		t.Fatalf("stale revision must not be refreshed, got %q", c.String())
	}
}

// Cross-origin requests are rejected before session handling and therefore do
// not refresh the session either.
func TestAPICrossOriginDoesNotRefresh(t *testing.T) {
	h := newTestHandler(t, 60)
	rev := auth.SessionRev(strings.Repeat("1", 64))
	token := auth.CreateSessionToken("alice", "testsecret", 10, rev)

	req := httptest.NewRequest("POST", "/api/services", strings.NewReader(`{"name":"x","port":8080}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", auth.SessionCookieName+"="+token)
	req.Header.Set("Origin", "http://evil.example")
	req.Host = "gw:30152"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
	if c := sessionCookieFromResponse(rr); c != nil {
		t.Fatalf("cross-origin request must not refresh the session, got %q", c.String())
	}
}

func TestAddServicePersistsRootAbsoluteAndHostnames(t *testing.T) {
	h, configDir := newVHostTestHandler(t)
	rr := apiPost(t, h, "/api/services",
		`{"name":"Hugo","port":1313,"root_absolute":true,"hostnames":["Hugo.Example.Test."]}`,
		"http://gw:30152")
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Service config.ServiceConfig `json:"service"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Service.RootAbsolute || !reflect.DeepEqual(resp.Service.Hostnames, []string{"hugo.example.test"}) {
		t.Fatalf("response service = %+v", resp.Service)
	}

	cfg, err := config.LoadUserConfig(config.UserConfigPath(configDir, "alice"))
	if err != nil {
		t.Fatal(err)
	}
	svc := config.ServiceByID(cfg.Services, resp.Service.ID)
	if svc == nil || !svc.RootAbsolute || !reflect.DeepEqual(svc.Hostnames, []string{"hugo.example.test"}) {
		t.Fatalf("persisted service = %+v", svc)
	}
}

func TestAddServiceRejectsBadHostnames(t *testing.T) {
	h, _ := newVHostTestHandler(t)
	cases := []string{
		`{"name":"x","port":8080,"hostnames":["bad"]}`,
		`{"name":"x","port":8080,"hostnames":["x.other.test"]}`,
		`{"name":"x","port":8080,"hostnames":["gw.example.test"]}`,
	}
	for _, body := range cases {
		rr := apiPost(t, h, "/api/services", body, "http://gw:30152")
		if rr.Code != http.StatusBadRequest {
			t.Errorf("body %s: status = %d, want 400 (%s)", body, rr.Code, rr.Body.String())
		}
	}
}

func TestAddServiceRejectsCrossUserHostname(t *testing.T) {
	h, configDir := newVHostTestHandler(t)
	bobPath := config.UserConfigPath(configDir, "bob")
	if err := os.MkdirAll(filepath.Dir(bobPath), 0700); err != nil {
		t.Fatal(err)
	}
	bobCfg := "auth:\n  password_hash: \"" + strings.Repeat("1", 64) + "\"\n" +
		"services:\n  - id: bobsvc\n    name: Bob\n    host: 127.0.0.1\n    port: 1314\n    path: /bob\n    hostnames:\n      - shared.example.test\n"
	if err := os.WriteFile(bobPath, []byte(bobCfg), 0600); err != nil {
		t.Fatal(err)
	}
	h.Registry.Reload()

	rr := apiPost(t, h, "/api/services",
		`{"name":"Mine","port":1315,"hostnames":["shared.example.test"]}`,
		"http://gw:30152")
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "bob/bobsvc") {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestUpdateServiceSetsAndClearsVHostFields(t *testing.T) {
	h, where := newVHostTestHandler(t)
	rr := apiPost(t, h, "/api/services", `{"name":"Hugo","port":1313}`, "http://gw:30152")
	if rr.Code != http.StatusCreated {
		t.Fatalf("add failed: %d %s", rr.Code, rr.Body.String())
	}
	var addResp struct {
		Service config.ServiceConfig `json:"service"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &addResp); err != nil {
		t.Fatal(err)
	}
	id := addResp.Service.ID

	rr = apiPut(t, h, "/api/services/"+id,
		`{"root_absolute":true,"hostnames":["hugo.example.test"]}`,
		"http://gw:30152")
	if rr.Code != http.StatusOK {
		t.Fatalf("update failed: %d %s", rr.Code, rr.Body.String())
	}
	cfg, err := config.LoadUserConfig(config.UserConfigPath(where, "alice"))
	if err != nil {
		t.Fatal(err)
	}
	svc := config.ServiceByID(cfg.Services, id)
	if svc == nil || !svc.RootAbsolute || !reflect.DeepEqual(svc.Hostnames, []string{"hugo.example.test"}) {
		t.Fatalf("after update: %+v", svc)
	}

	rr = apiPut(t, h, "/api/services/"+id, `{"root_absolute":false,"hostnames":[]}`, "http://gw:30152")
	if rr.Code != http.StatusOK {
		t.Fatalf("clear failed: %d %s", rr.Code, rr.Body.String())
	}
	cfg, _ = config.LoadUserConfig(config.UserConfigPath(where, "alice"))
	svc = config.ServiceByID(cfg.Services, id)
	if svc == nil || svc.RootAbsolute || len(svc.Hostnames) != 0 {
		t.Fatalf("after clear: %+v", svc)
	}
}

func TestUpdateServiceRejectsCrossUserHostname(t *testing.T) {
	h, configDir := newVHostTestHandler(t)
	bobPath := config.UserConfigPath(configDir, "bob")
	if err := os.MkdirAll(filepath.Dir(bobPath), 0700); err != nil {
		t.Fatal(err)
	}
	bobCfg := "auth:\n  password_hash: \"" + strings.Repeat("1", 64) + "\"\n" +
		"services:\n  - id: bobsvc\n    name: Bob\n    host: 127.0.0.1\n    port: 1314\n    path: /bob\n    hostnames:\n      - shared.example.test\n"
	if err := os.WriteFile(bobPath, []byte(bobCfg), 0600); err != nil {
		t.Fatal(err)
	}
	h.Registry.Reload()

	rr := apiPost(t, h, "/api/services", `{"name":"Mine","port":1315}`, "http://gw:30152")
	if rr.Code != http.StatusCreated {
		t.Fatalf("add failed: %d %s", rr.Code, rr.Body.String())
	}
	var addResp struct {
		Service config.ServiceConfig `json:"service"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &addResp); err != nil {
		t.Fatal(err)
	}
	rr = apiPut(t, h, "/api/services/"+addResp.Service.ID,
		`{"hostnames":["shared.example.test"]}`, "http://gw:30152")
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "bob/bobsvc") {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

// A name update is validated after trimming and must be persisted trimmed too;
// otherwise "  Foo  " is stored while the length check used "Foo".
func TestUpdateServiceTrimsName(t *testing.T) {
	h := newTestHandler(t)
	rr := apiPost(t, h, "/api/services", `{"name":"x","port":8080}`, "http://gw:30152")
	if rr.Code != http.StatusCreated {
		t.Fatalf("setup add failed: %d body=%s", rr.Code, rr.Body.String())
	}
	rr = apiPut(t, h, "/api/services/x", `{"name":"  Renamed  "}`, "http://gw:30152")
	if rr.Code != http.StatusOK {
		t.Fatalf("update failed: %d body=%s", rr.Code, rr.Body.String())
	}
	user := h.Registry.GetUser("alice")
	if user == nil {
		t.Fatal("alice missing")
	}
	cfg, err := config.LoadUserConfig(user.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	svc := config.ServiceByID(cfg.Services, "x")
	if svc == nil {
		t.Fatal("service x missing after update")
	}
	if svc.Name != "Renamed" {
		t.Fatalf("name = %q, want trimmed %q", svc.Name, "Renamed")
	}
}

func TestUpdateLayoutRejectsOversizedCategory(t *testing.T) {
	h := newTestHandler(t)
	long := strings.Repeat("c", 101)
	body := `{"items":[{"id":"x","order":0,"category":"` + long + `"}]}`
	rr := apiPut(t, h, "/api/services/layout", body, "http://gw:30152")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized category, got %d body=%s", rr.Code, rr.Body.String())
	}
}
