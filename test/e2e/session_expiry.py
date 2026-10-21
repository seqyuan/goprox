#!/usr/bin/env python3
"""End-to-end regression: an expired dashboard session must not surface a raw
"Unauthorized" error in the add-service form.

Scenario: log in, open the add form, let the session expire while the tab is
idle (no API requests are sent), then submit. The gateway returns 401; the
dashboard must redirect to /login and stash the form values. After logging in
again, the add form must reopen with the draft still filled in.

The Go test TestE2EExpiredSessionRedirectsAndRestoresDraft starts the server
with a short session TTL and runs this script. It is also runnable standalone:

    GOPROX_E2E_URL=http://127.0.0.1:30199/ \
    GOPROX_E2E_USER=alice GOPROX_E2E_PASS=testpass123 \
    python3 test/e2e/session_expiry.py

Exit codes: 0 = pass, 3 = no browser available (caller should skip), else fail.
"""

import os
import sys
import time

from playwright.sync_api import sync_playwright


def env(name, default=None):
    value = os.environ.get(name, default)
    if value is None:
        print(f"missing required env var {name}", file=sys.stderr)
        sys.exit(2)
    return value


def login(page, user, password):
    page.fill("#username", user)
    page.fill("#password", password)
    page.click('form[action="/login"] button[type="submit"]')
    page.wait_for_load_state("networkidle")


def main():
    base_url = env("GOPROX_E2E_URL", "http://127.0.0.1:30199/")
    user = env("GOPROX_E2E_USER", "alice")
    password = env("GOPROX_E2E_PASS", "testpass123")
    # Must exceed the server's session_ttl; the Go test sets it to 10s.
    expiry_wait = float(env("GOPROX_E2E_EXPIRY_WAIT", "11"))
    draft_name = env("GOPROX_E2E_DRAFT_NAME", "Draft Card")
    draft_port = env("GOPROX_E2E_DRAFT_PORT", "18080")

    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(headless=True)
        except Exception as exc:  # browser binary not installed
            print(f"SKIP_NO_BROWSER: {exc}", file=sys.stderr)
            sys.exit(3)

        page = browser.new_page()
        try:
            page.goto(base_url, wait_until="networkidle")
            if page.locator("#username").count() > 0:
                login(page, user, password)

            page.wait_for_selector("#fab-add")
            page.click("#fab-add")
            page.wait_for_selector("#add-modal.open")
            page.fill("#add-name", draft_name)
            page.fill("#add-port", draft_port)

            # No API requests happen while the tab sits idle, so the session
            # expires instead of being refreshed by the sliding window.
            time.sleep(expiry_wait)

            page.click('#add-form button[type="submit"]')

            # A 401 must navigate to the login page, not render "Unauthorized"
            # inside the form.
            page.wait_for_url("**/login", timeout=15000)
            if not page.url.rstrip("/").endswith("/login"):
                raise AssertionError(f"expected /login, got {page.url}")

            login(page, user, password)

            # The dashboard restores the draft and reopens the add form.
            page.wait_for_selector("#add-modal.open", timeout=15000)
            name = page.input_value("#add-name")
            port = page.input_value("#add-port")
            if name != draft_name:
                raise AssertionError(f"draft name not restored: {name!r} != {draft_name!r}")
            if port != draft_port:
                raise AssertionError(f"draft port not restored: {port!r} != {draft_port!r}")

            print("OK: expired session redirected to /login and restored the add draft")
        finally:
            browser.close()


if __name__ == "__main__":
    main()
