package main

import (
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/seqyuan/goprox/internal/auth"
	"github.com/seqyuan/goprox/internal/config"
	"github.com/seqyuan/goprox/internal/server"
)

// TestE2EEditBandwidthPreservedThroughRename drives a real Chromium (via the
// Playwright script in test/e2e/) through login + edit to prove that a saved
// byte-per-second cap such as 10000000 — shown in the form as "9.537" — no
// longer blocks the edit form from submitting.
//
// Regression being guarded: with step="0.1" the number input failed the
// browser's step validation, so clicking 保存 never fired the submit handler
// and even an unrelated name change was stuck. The fix is step="any".
//
// Skips (rather than fails) when python3, the playwright module, or a browser
// binary are unavailable, mirroring TestDashboardUtilSlugParity's node skip.
func TestE2EEditBandwidthPreservedThroughRename(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed; skipping browser E2E test")
	}
	if out, err := exec.Command(python, "-c", "import playwright").CombinedOutput(); err != nil {
		t.Skipf("python playwright module not installed; skipping browser E2E test: %s", out)
	}

	dir := t.TempDir()
	state, err := config.LoadState(config.StatePath(dir))
	if err != nil {
		t.Fatal(err)
	}

	const (
		username = "alice"
		password = "testpass123"
		svcID    = "app"
		newName  = "App Renamed"
		bwLimit  = int64(10000000)
	)
	cfgPath := config.UserConfigPath(dir, username)
	if err := config.EnsureUserConfig(cfgPath); err != nil {
		t.Fatal(err)
	}
	if err := config.UpdatePasswordHash(cfgPath, auth.HashPassword(password)); err != nil {
		t.Fatal(err)
	}
	if _, err := config.AddService(cfgPath, config.ServiceConfig{
		ID: svcID, Name: "App", Host: "127.0.0.1", Port: 18080,
		Path: "/app", WebSocket: true, BWLimit: bwLimit,
	}); err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(server.New(state, dir).Handler())
	defer ts.Close()

	cmd := exec.Command(python, filepath.Join("test", "e2e", "edit_bandwidth.py"))
	cmd.Env = append(os.Environ(),
		"GOPROX_E2E_URL="+ts.URL+"/",
		"GOPROX_E2E_USER="+username,
		"GOPROX_E2E_PASS="+password,
		"GOPROX_E2E_SERVICE_ID="+svcID,
		"GOPROX_E2E_NEW_NAME="+newName,
	)
	out, err := cmd.CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 3 {
		t.Skipf("playwright browser unavailable; skipping browser E2E test: %s", out)
	}
	if err != nil {
		t.Fatalf("browser E2E failed: %v\n%s", err, out)
	}

	// The rename persisted and the untouched cap survived the MB round-trip.
	cfg, err := config.LoadUserConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	svc := config.ServiceByID(cfg.Services, svcID)
	if svc == nil {
		t.Fatalf("service %q disappeared after edit", svcID)
	}
	if svc.Name != newName {
		t.Fatalf("name not saved: got %q want %q", svc.Name, newName)
	}
	if svc.BWLimit != bwLimit {
		t.Fatalf("bandwidth cap changed: got %d want %d", svc.BWLimit, bwLimit)
	}
	if svc.Path != "/app" {
		t.Fatalf("path changed unexpectedly: %q", svc.Path)
	}
	t.Logf("E2E: %q renamed to %q, bwlimit preserved at %d", svcID, newName, svc.BWLimit)
}

// TestE2EExpiredSessionRedirectsAndRestoresDraft drives a real Chromium
// through the reported failure mode: the dashboard tab sits idle until the
// gateway session expires, then the user submits the add form. The response is
// 401, which must redirect to /login instead of showing "Unauthorized" in the
// form; the draft must be restored after logging in again.
//
// The server is started with a 10s TTL so the test can exercise real expiry
// without waiting a day. Skips when python3/playwright/browser are unavailable.
func TestE2EExpiredSessionRedirectsAndRestoresDraft(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed; skipping browser E2E test")
	}
	if out, err := exec.Command(python, "-c", "import playwright").CombinedOutput(); err != nil {
		t.Skipf("python playwright module not installed; skipping browser E2E test: %s", out)
	}

	dir := t.TempDir()
	state, err := config.LoadState(config.StatePath(dir))
	if err != nil {
		t.Fatal(err)
	}
	state.Auth.SessionTTL = 10

	const (
		username  = "alice"
		password  = "testpass123"
		draftName = "Draft Card"
		draftPort = "18080"
	)
	cfgPath := config.UserConfigPath(dir, username)
	if err := config.EnsureUserConfig(cfgPath); err != nil {
		t.Fatal(err)
	}
	if err := config.UpdatePasswordHash(cfgPath, auth.HashPassword(password)); err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(server.New(state, dir).Handler())
	defer ts.Close()

	cmd := exec.Command(python, filepath.Join("test", "e2e", "session_expiry.py"))
	cmd.Env = append(os.Environ(),
		"GOPROX_E2E_URL="+ts.URL+"/",
		"GOPROX_E2E_USER="+username,
		"GOPROX_E2E_PASS="+password,
		"GOPROX_E2E_EXPIRY_WAIT=11",
		"GOPROX_E2E_DRAFT_NAME="+draftName,
		"GOPROX_E2E_DRAFT_PORT="+draftPort,
	)
	out, err := cmd.CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 3 {
		t.Skipf("playwright browser unavailable; skipping browser E2E test: %s", out)
	}
	if err != nil {
		t.Fatalf("browser E2E failed: %v\n%s", err, out)
	}

	// The expired POST must not have created a service.
	cfg, err := config.LoadUserConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Services) != 0 {
		t.Fatalf("expired POST created %d service(s): %+v", len(cfg.Services), cfg.Services)
	}
}
