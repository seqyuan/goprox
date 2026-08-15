package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// A bwlimit-capped service must still deliver intact bodies for both the
// injected-HTML path (defer wrapping happens after <base> injection) and the
// pass-through non-HTML path.
func TestBWLimitDoesNotCorruptResponse(t *testing.T) {
	t.Run("html injection intact", func(t *testing.T) {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("<html><head></head><body>hello</body></html>"))
		}))
		defer backend.Close()
		host, port := splitHostPort(backend.Listener.Addr().String())
		svc := &config.ServiceConfig{Host: host, Port: mustAtoi(t, port), Path: "/jupyter", BWLimit: 1 << 20}
		rp := NewReverseProxy(svc, testFwdCtx())

		rec := httptest.NewRecorder()
		rp.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
		body := rec.Body.String()
		if !strings.Contains(body, "<base") || !strings.Contains(body, "hello") {
			t.Fatalf("bwlimit broke html injection/passthrough: %q", body)
		}
	})

	t.Run("non-html passthrough intact", func(t *testing.T) {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"ok":true}`))
		}))
		defer backend.Close()
		host, port := splitHostPort(backend.Listener.Addr().String())
		svc := &config.ServiceConfig{Host: host, Port: mustAtoi(t, port), Path: "/api", BWLimit: 1 << 20}
		rp := NewReverseProxy(svc, testFwdCtx())

		rec := httptest.NewRecorder()
		rp.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
		if rec.Body.String() != `{"ok":true}` {
			t.Fatalf("bwlimit corrupted non-html body: %q", rec.Body.String())
		}
	})
}

// A bwlimit-capped upload must still reach the backend with its body intact.
func TestBWLimitPreservesUpload(t *testing.T) {
	var gotBody string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Write([]byte("ok"))
	}))
	defer backend.Close()
	host, port := splitHostPort(backend.Listener.Addr().String())
	svc := &config.ServiceConfig{Host: host, Port: mustAtoi(t, port), Path: "/app", BWLimit: 1 << 20}
	rp := NewReverseProxy(svc, testFwdCtx())

	req := httptest.NewRequest("POST", "/", strings.NewReader("upload-me"))
	rp.ServeHTTP(httptest.NewRecorder(), req)
	if gotBody != "upload-me" {
		t.Fatalf("bwlimit corrupted upload: %q", gotBody)
	}
}

// A browser-sent Origin must be rewritten to the backend's own authority so
// backends that enforce a Host/Origin same-origin check (e.g. dsh's /api
// trust fence, Jupyter CSRF) accept requests proxied from another origin.
func TestOriginRewrittenToBackendAuthority(t *testing.T) {
	var gotOrigin, gotHost string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOrigin = r.Header.Get("Origin")
		gotHost = r.Host
		w.Write([]byte("ok"))
	}))
	defer backend.Close()
	host, port := splitHostPort(backend.Listener.Addr().String())
	svc := &config.ServiceConfig{Host: host, Port: mustAtoi(t, port), Path: "/app"}

	req := httptest.NewRequest("POST", "/api/x", nil)
	req.Host = "192.168.0.106:7658"
	req.Header.Set("Origin", "http://192.168.0.106:7658")
	fc := BuildProxyForwardContext(req, "alice", "/app", false)
	rp := NewReverseProxy(svc, fc)

	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	wantOrigin := "http://" + gotHost
	if gotOrigin != wantOrigin {
		t.Fatalf("backend Origin = %q, want %q (matching rewritten Host)", gotOrigin, wantOrigin)
	}
}

// A request without an Origin header must not gain one (curl/CLI clients).
func TestNoOriginHeaderNotInvented(t *testing.T) {
	var gotOrigin string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOrigin = r.Header.Get("Origin")
		w.Write([]byte("ok"))
	}))
	defer backend.Close()
	host, port := splitHostPort(backend.Listener.Addr().String())
	svc := &config.ServiceConfig{Host: host, Port: mustAtoi(t, port), Path: "/app"}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Del("Origin")
	fc := BuildProxyForwardContext(req, "alice", "/app", false)
	rp := NewReverseProxy(svc, fc)

	rp.ServeHTTP(httptest.NewRecorder(), req)

	if gotOrigin != "" {
		t.Fatalf("backend received an invented Origin %q", gotOrigin)
	}
}

// A 101 Switching Protocols (WebSocket) upgrade must not have its body wrapped
// by the bandwidth limiter: ReverseProxy needs the raw io.ReadWriteCloser to
// hand the tunnel to the client. Regression for "101 switching protocols
// response with non-writable body" under a per-service bwlimit.
func TestWebSocketUpgradeWithBwlimit(t *testing.T) {
	// Minimal raw upgrade backend: respond 101 and echo a byte.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		req := string(buf[:n])
		if !strings.Contains(req, "Upgrade: websocket") {
			conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
			return
		}
		conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
		// echo one byte back through the tunnel
		conn.Read(buf)
		conn.Write([]byte("Z"))
	}()

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("GET", "http://127.0.0.1:"+portStr+"/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")

	// A real client connection is required: the upgrade hijacks the socket.
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// Server-side forwarding happens through the proxy on a real listener.
	pln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pln.Close()
	_, pportStr, _ := net.SplitHostPort(pln.Addr().String())
	pport, _ := strconv.Atoi(pportStr)
	psvc := &config.ServiceConfig{Host: "127.0.0.1", Port: pport, Path: "/app", BWLimit: 1024}
	prp := NewReverseProxy(psvc, testFwdCtx())

	// Serve the reverse proxy over a real listener so the hijack works.
	httpSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prp.ServeHTTP(w, r)
	})}
	go httpSrv.Serve(pln)
	defer httpSrv.Close()

	req.URL = &url.URL{Scheme: "http", Host: pln.Addr().String(), Path: "/ws"}
	if err := req.Write(client); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(client)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101, got %d", resp.StatusCode)
	}
	// tunnel is now raw: client writes a byte, backend echoes "Z"
	if _, err := client.Write([]byte("A")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 1)
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatalf("tunnel read failed: %v", err)
	}
	if got[0] != 'Z' {
		t.Fatalf("tunnel echo = %q, want Z", got)
	}
}

// A third-party Origin (CORS client on another site) must pass through
// untouched: only same-origin browser requests through the gateway get the
// rewrite that keeps backend Host/Origin checks coherent.
func TestThirdPartyOriginNotRewritten(t *testing.T) {
	var gotOrigin string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOrigin = r.Header.Get("Origin")
		w.Write([]byte("ok"))
	}))
	defer backend.Close()
	host, port := splitHostPort(backend.Listener.Addr().String())
	svc := &config.ServiceConfig{Host: host, Port: mustAtoi(t, port), Path: "/app"}

	req := httptest.NewRequest("GET", "/api/x", nil)
	req.Host = "192.168.0.106:7658"
	req.Header.Set("Origin", "http://attacker.example")
	fc := BuildProxyForwardContext(req, "alice", "/app", false)
	rp := NewReverseProxy(svc, fc)

	rp.ServeHTTP(httptest.NewRecorder(), req)

	if gotOrigin != "http://attacker.example" {
		t.Fatalf("third-party Origin was rewritten to %q", gotOrigin)
	}
}

// Proxied HTML must receive the webcompat polyfill next to the injected base
// tag, so apps relying on crypto.randomUUID keep working over plain HTTP.
func TestHTMLGetsPolyfillWithBase(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><head><title>x</title></head><body>ok</body></html>"))
	}))
	defer backend.Close()
	host, port := splitHostPort(backend.Listener.Addr().String())
	svc := &config.ServiceConfig{Host: host, Port: mustAtoi(t, port), Path: "/app"}
	rp := NewReverseProxy(svc, testFwdCtx())

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, `<base href="/proxy/alice/jupyter/">`) {
		t.Fatalf("missing injected <base> in %q", body)
	}
	if !strings.Contains(body, "randomUUID") {
		t.Fatalf("missing webcompat polyfill in %q", body)
	}
	// The polyfill must be injected into <head>, ahead of any scripts.
	if !strings.Contains(body, "<head><title>x</title>") && !strings.Contains(body, "<head><base") {
		t.Fatalf("polyfill/base not at head position: %q", body)
	}
}

// A page that already ships its own <base> tag must not get a second one, but
// still receives the polyfill (the two injections are independent).
func TestHTMLWithOwnBaseStillGetsPolyfill(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><head><base href=\"/self/\"><title>x</title></head><body>ok</body></html>"))
	}))
	defer backend.Close()
	host, port := splitHostPort(backend.Listener.Addr().String())
	svc := &config.ServiceConfig{Host: host, Port: mustAtoi(t, port), Path: "/app"}
	rp := NewReverseProxy(svc, testFwdCtx())

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	body := rec.Body.String()
	if strings.Count(body, "<base") != 1 {
		t.Fatalf("expected exactly one <base> tag (the backend's own), got %q", body)
	}
	if !strings.Contains(body, "randomUUID") {
		t.Fatalf("missing webcompat polyfill in %q", body)
	}
}

// Non-HTML responses must not receive the polyfill.
func TestNonHTMLNoPolyfill(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte("crypto.randomUUID()"))
	}))
	defer backend.Close()
	host, port := splitHostPort(backend.Listener.Addr().String())
	svc := &config.ServiceConfig{Host: host, Port: mustAtoi(t, port), Path: "/app"}
	rp := NewReverseProxy(svc, testFwdCtx())

	req := httptest.NewRequest("GET", "/x.js", nil)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	if rec.Body.String() != "crypto.randomUUID()" {
		t.Fatalf("JS body was altered: %q", rec.Body.String())
	}
}
