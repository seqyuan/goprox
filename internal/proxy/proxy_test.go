package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/seqyuan/goprox/internal/config"
)

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

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

func testFwdCtx() ProxyForwardContext {
	return ProxyForwardContext{Prefix: "/proxy/alice/jupyter", Base: "/proxy/alice/jupyter/"}
}

// The injected <base> must be the directory of the served document, not the
// service prefix, so relative links in subdirectory HTML files resolve there.
func TestBaseForPath(t *testing.T) {
	cases := []struct {
		prefix    string
		remaining string
		want      string
	}{
		{"/proxy/alice/docs", "/", "/proxy/alice/docs/"},
		{"/proxy/alice/docs", "/report/page.html", "/proxy/alice/docs/report/"},
		{"/proxy/alice/docs", "/report/", "/proxy/alice/docs/report/"},
		{"/proxy/alice/docs", "/my dir/page.html", "/proxy/alice/docs/my%20dir/"},
	}
	for _, c := range cases {
		if got := BaseForPath(c.prefix, c.remaining); got != c.want {
			t.Errorf("BaseForPath(%q, %q) = %q, want %q", c.prefix, c.remaining, got, c.want)
		}
	}
}

func TestRewriteLocationRelativePath(t *testing.T) {
	got, ok := rewriteLocation("/lab?x=1", "", testFwdCtx(), "127.0.0.1:8888")
	if !ok || got != "/proxy/alice/jupyter/lab?x=1" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestRewriteLocationAlreadyPrefixed(t *testing.T) {
	got, ok := rewriteLocation("/proxy/alice/jupyter/lab", "", testFwdCtx(), "127.0.0.1:8888")
	if ok {
		t.Fatalf("already-prefixed Location must not be rewritten, got %q", got)
	}
}

func TestRewriteLocationAbsoluteBackendURL(t *testing.T) {
	// Backend redirects to its own absolute URL (common when it derives URLs
	// from its Host header) — must become a gateway-relative URL.
	got, ok := rewriteLocation("http://127.0.0.1:8888/lab", "", testFwdCtx(), "127.0.0.1:8888")
	if !ok || got != "/proxy/alice/jupyter/lab" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestRewriteLocationAbsoluteLoopbackSpelling(t *testing.T) {
	// localhost vs 127.0.0.1 spellings of the same backend must both rewrite.
	got, ok := rewriteLocation("http://localhost:8888/lab", "", testFwdCtx(), "127.0.0.1:8888")
	if !ok || got != "/proxy/alice/jupyter/lab" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestRewriteLocationExternalURLUntouched(t *testing.T) {
	// SSO / external redirects must pass through exactly as-is.
	got, ok := rewriteLocation("https://sso.example.com/auth?next=x", "", testFwdCtx(), "127.0.0.1:8888")
	if ok || got != "https://sso.example.com/auth?next=x" {
		t.Fatalf("external redirect must be untouched, got %q ok=%v", got, ok)
	}
}

func TestRewriteLocationProtocolRelativeUntouched(t *testing.T) {
	got, ok := rewriteLocation("//cdn.example.com/app.js", "", testFwdCtx(), "127.0.0.1:8888")
	if ok {
		t.Fatalf("protocol-relative URL must not be rewritten, got %q", got)
	}
}

func TestRewriteLocationBackendPathStrip(t *testing.T) {
	got, ok := rewriteLocation("/app/index.html", "/app/index.html", testFwdCtx(), "127.0.0.1:8888")
	if !ok || got != "/proxy/alice/jupyter/" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
	got, ok = rewriteLocation("/app/assets/main.js", "/app", testFwdCtx(), "127.0.0.1:8888")
	if !ok || got != "/proxy/alice/jupyter/assets/main.js" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

// A chunked HTML response larger than the injection cap must be streamed
// through in full, without <base> injection and without truncation, so
// memory stays bounded.
func TestOversizeChunkedHTMLForwardedWithoutInjection(t *testing.T) {
	old := maxInjectHTML
	maxInjectHTML = 512
	defer func() { maxInjectHTML = old }()

	payload := strings.Repeat("<p>x</p>", 1000) // 7000 bytes, well over the 512 cap
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		io.WriteString(w, payload) // no Content-Length => chunked
	}))
	defer backend.Close()

	host, port := splitHostPort(backend.Listener.Addr().String())
	svc := &config.ServiceConfig{Host: host, Port: mustAtoi(t, port), Path: "/jupyter"}
	fc := testFwdCtx()
	rp := NewReverseProxy(svc, fc)

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	got := rec.Body.String()
	if got != payload {
		t.Fatalf("oversize chunked body altered: got %d bytes, want %d (prefix %q)", len(got), len(payload), got[:min(len(got), 60)])
	}
	if strings.Contains(got, "<base") {
		t.Fatal("oversize chunked body must not be injected with <base>")
	}
}

func TestIsStaticAssetPath(t *testing.T) {
	static := []string{
		"/_next/static/chunks/webpack.js",
		"/static/css/app.css",
		"/assets/logo.png",
		"/favicon.svg",
		"/app.js",
		"/font.woff2",
		"/data.json",
		"/image.webp",
	}
	html := []string{
		"/",
		"/workspace",
		"/login",
		"/api/auth/login",
		"/page.html",
		"/index.htm",
		"/doc",
	}
	for _, p := range static {
		if !isStaticAssetPath(p) {
			t.Errorf("isStaticAssetPath(%q) = false, want true", p)
		}
	}
	for _, p := range html {
		if isStaticAssetPath(p) {
			t.Errorf("isStaticAssetPath(%q) = true, want false", p)
		}
	}
}

// Static assets must keep the browser's Accept-Encoding so compression is
// preserved end-to-end.
func TestStaticAssetKeepsAcceptEncoding(t *testing.T) {
	var gotAE string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAE = r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte("ok"))
	}))
	defer backend.Close()
	host, port := splitHostPort(backend.Listener.Addr().String())
	svc := &config.ServiceConfig{Host: host, Port: mustAtoi(t, port), Path: "/app"}
	rp := NewReverseProxy(svc, testFwdCtx())

	req := httptest.NewRequest("GET", "/app.js", nil)
	req.Header.Set("Accept-Encoding", "gzip, br")
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	if gotAE != "gzip, br" {
		t.Fatalf("static asset should keep Accept-Encoding, got %q", gotAE)
	}
}

// HTML must strip Accept-Encoding so <base> injection sees a decompressed body.
func TestHTMLStripsAcceptEncoding(t *testing.T) {
	var gotAE string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAE = r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><head></head><body>x</body></html>"))
	}))
	defer backend.Close()
	host, port := splitHostPort(backend.Listener.Addr().String())
	svc := &config.ServiceConfig{Host: host, Port: mustAtoi(t, port), Path: "/app"}
	rp := NewReverseProxy(svc, testFwdCtx())

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip, br")
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	if strings.Contains(gotAE, "br") {
		t.Fatalf("HTML should strip the browser's Accept-Encoding (no br), got %q", gotAE)
	}
}

// A client-supplied X-Forwarded-For must be dropped: the backend receives only
// the peer address computed by ClientIP, never an attacker-controlled value
// that a backend might trust for logging or IP-based access control.
func TestClientForwardedForNotForwarded(t *testing.T) {
	var gotXFF string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotXFF = r.Header.Get("X-Forwarded-For")
		w.Write([]byte("ok"))
	}))
	defer backend.Close()
	host, port := splitHostPort(backend.Listener.Addr().String())
	svc := &config.ServiceConfig{Host: host, Port: mustAtoi(t, port), Path: "/app"}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.9:4321"
	req.Header.Set("X-Forwarded-For", "6.6.6.6")
	fc := BuildProxyForwardContext(req, "alice", "/app", false)
	rp := NewReverseProxy(svc, fc)

	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	if gotXFF != "203.0.113.9" {
		t.Fatalf("client-supplied XFF must not be forwarded; got %q, want the peer IP 203.0.113.9", gotXFF)
	}
}
