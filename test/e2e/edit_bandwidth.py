#!/usr/bin/env python3
"""End-to-end regression: editing a service that has a non-round bandwidth cap.

Scenario (the bug this guards): a service saved with a byte-per-second cap that
is not an exact multiple of MB, e.g. bwlimit: 10000000, is shown in the edit
form as "9.537". With step="0.1" the number input failed the browser's step
validation, so clicking 保存 never fired the submit handler and the whole form
(including an unrelated name change) was stuck. The fix is step="any"; this test
drives a real Chromium through login + edit and asserts the save goes through.

The Go test TestE2EEditBandwidthPreservedThroughRename starts the server and
runs this script, then checks the persisted config. The script is also runnable
standalone against any running instance:

    GOPROX_E2E_URL=http://127.0.0.1:30199/ \
    GOPROX_E2E_USER=alice GOPROX_E2E_PASS=testpass123 \
    GOPROX_E2E_SERVICE_ID=app GOPROX_E2E_NEW_NAME='App Renamed' \
    python3 test/e2e/edit_bandwidth.py

Exit codes: 0 = pass, 3 = no browser available (caller should skip), else fail.
"""

import os
import sys

from playwright.sync_api import sync_playwright


def env(name, default=None):
    value = os.environ.get(name, default)
    if value is None:
        print(f"missing required env var {name}", file=sys.stderr)
        sys.exit(2)
    return value


def main():
    base_url = env("GOPROX_E2E_URL", "http://127.0.0.1:30199/")
    user = env("GOPROX_E2E_USER", "alice")
    password = env("GOPROX_E2E_PASS", "testpass123")
    service_id = env("GOPROX_E2E_SERVICE_ID", "app")
    new_name = env("GOPROX_E2E_NEW_NAME", "App Renamed")

    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(headless=True)
        except Exception as exc:  # browser binary not installed
            print(f"SKIP_NO_BROWSER: {exc}", file=sys.stderr)
            sys.exit(3)

        page = browser.new_page()
        try:
            page.goto(base_url)
            page.wait_for_load_state("networkidle")

            # Log in when the login form is present (fresh context always is).
            if page.locator("#username").count() > 0:
                page.fill("#username", user)
                page.fill("#password", password)
                page.click('form[action="/login"] button[type="submit"]')
                page.wait_for_load_state("networkidle")

            assert page.locator(".service-card").count() >= 1, "no service cards rendered"

            # The card toolbar is hover/focus-revealed on fine pointers.
            card = page.locator(f'.service-card[data-id="{service_id}"]')
            assert card.count() == 1, f"service card {service_id!r} not found"
            card.hover()
            card.locator(".card-edit").click()
            page.wait_for_selector("#edit-modal.open")

            shown_bw = page.input_value("#edit-bwlimit")
            print(f"bandwidth field shows: {shown_bw!r} (step={page.get_attribute('#edit-bwlimit', 'step')})")
            # This is the value the old step="0.1" rejected.
            assert shown_bw == "9.537", f"expected the 10000000 B/s cap to render as 9.537, got {shown_bw!r}"
            assert page.eval_on_selector("#edit-bwlimit", "el => el.checkValidity()") is True, \
                "bandwidth field is not valid: the form would be blocked from submitting"

            # Change only the name; the bandwidth field stays untouched.
            page.fill("#edit-name", new_name)
            page.click('#edit-form button[type="submit"]')

            # Success closes the sheet and shows the toast; failure keeps the
            # modal open and blocks here (the regression we are guarding).
            page.wait_for_selector("#toast", state="visible", timeout=8000)
            toast = page.inner_text("#toast")
            assert "已保存" in toast, f"unexpected toast: {toast!r}"
            assert page.locator("#edit-modal.open").count() == 0, "edit modal stayed open after save"
            assert page.locator("#edit-error").is_visible() is False, "inline form error shown"

            print(f"E2E_OK: renamed {service_id!r} to {new_name!r} with the bandwidth cap untouched")
        finally:
            browser.close()


if __name__ == "__main__":
    main()
