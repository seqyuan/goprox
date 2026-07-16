package proxy

import "testing"

func TestJoinBackendPathDirectory(t *testing.T) {
	got := joinBackendPath("/app", "/assets/main.js")
	if got != "/app/assets/main.js" {
		t.Fatalf("expected /app/assets/main.js, got %q", got)
	}
}

func TestJoinBackendPathFileRoot(t *testing.T) {
	got := joinBackendPath("/app/index.html", "/")
	if got != "/app/index.html" {
		t.Fatalf("expected /app/index.html, got %q", got)
	}
}

func TestJoinBackendPathFileSubresource(t *testing.T) {
	got := joinBackendPath("/app/index.html", "/assets/main.js")
	if got != "/app/assets/main.js" {
		t.Fatalf("expected /app/assets/main.js, got %q", got)
	}
}
