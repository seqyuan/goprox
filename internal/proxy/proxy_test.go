package proxy

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/seqyuan/goprox/internal/auth"
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

// Lightweight SSO: when enabled, the backend receives the authenticated
// session user in the configured header, and a client-supplied value is
// overwritten (never passed through) so the browser cannot forge an identity.
func TestSSOUserHeaderSetFromSession(t *testing.T) {
	tests := []struct {
		name       string
		headerName string
		clientVal  string
	}{
		{"default name, no forgery", "X-Authenticated-User", ""},
		{"default name, forged", "X-Authenticated-User", "admin"},
		{"custom name, forged", "X-Custom-User", "root"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotHeader, gotSig string
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotHeader = r.Header.Get(tt.headerName)
				gotSig = r.Header.Get(tt.headerName + "-Signature")
				w.Write([]byte("ok"))
			}))
			defer backend.Close()
			host, port := splitHostPort(backend.Listener.Addr().String())
			svc := &config.ServiceConfig{Host: host, Port: mustAtoi(t, port), Path: "/app"}
			fc := testFwdCtx()
			fc.Username = "alice"
			fc.SSO = config.SSOState{UserHeader: tt.headerName}

			req := httptest.NewRequest("GET", "/", nil)
			if tt.clientVal != "" {
				req.Header.Set(tt.headerName, tt.clientVal)
			}
			rp := NewReverseProxy(svc, fc)
			rec := httptest.NewRecorder()
			rp.ServeHTTP(rec, req)

			if gotHeader != "alice" {
				t.Fatalf("backend got %s=%q, want the session user %q", tt.headerName, gotHeader, "alice")
			}
			if gotSig != "" {
				t.Fatalf("unsigned SSO must not send a signature header, got %q", gotSig)
			}
		})
	}
}

// With a shared secret configured, the gateway signs the user header with
// HMAC-SHA256 over SSOSignaturePrefix+username (base64url, unpadded) so a
// backend can verify the identity without relying on network isolation alone.
// A client-supplied signature is overwritten, not passed through.
func TestSSOUserHeaderHMACSignature(t *testing.T) {
	const secret = "test-sso-secret"
	var gotUser, gotSig string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser = r.Header.Get("X-Authenticated-User")
		gotSig = r.Header.Get("X-Authenticated-User-Signature")
		w.Write([]byte("ok"))
	}))
	defer backend.Close()
	host, port := splitHostPort(backend.Listener.Addr().String())
	svc := &config.ServiceConfig{Host: host, Port: mustAtoi(t, port), Path: "/app"}
	fc := testFwdCtx()
	fc.Username = "alice"
	fc.SSO = config.SSOState{UserHeader: "X-Authenticated-User", HMACSecret: secret}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Authenticated-User", "admin")
	req.Header.Set("X-Authenticated-User-Signature", "forged")
	rp := NewReverseProxy(svc, fc)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	if gotUser != "alice" {
		t.Fatalf("backend got user %q, want %q", gotUser, "alice")
	}
	want := hmacSHA256Base64URL(secret, SSOSignaturePrefix+"alice")
	if gotSig != want {
		t.Fatalf("backend got signature %q, want %q", gotSig, want)
	}
}

func hmacSHA256Base64URL(secret, msg string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Well-known identity headers (JupyterHub, oauth2-proxy, nginx auth_request,
// mod_authnz_forwarded, ...) must never pass through from the browser: they
// are stripped even when SSO is disabled or uses a different header name,
// otherwise a backend trusting one of them could be spoofed through the
// gateway. With SSO enabled under a custom name, the configured header
// carries the session user while the known names stay stripped.
func TestSSOIdentityHeadersStripped(t *testing.T) {
	known := []string{"X-Authenticated-User", "X-Forwarded-User", "X-Auth-Request-User", "Remote-User", "Remote_User"}
	for _, tc := range []struct {
		name       string
		sso        config.SSOState
		clientVal  string
		wantCustom string
	}{
		{"disabled", config.SSOState{}, "admin", "admin"}, // unknown names pass through untouched
		{"enabled with custom name", config.SSOState{UserHeader: "X-Custom-User"}, "admin", "alice"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got map[string]string
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = make(map[string]string)
				for _, n := range known {
					got[n] = r.Header.Get(n)
				}
				got["X-Custom-User"] = r.Header.Get("X-Custom-User")
				w.Write([]byte("ok"))
			}))
			defer backend.Close()
			host, port := splitHostPort(backend.Listener.Addr().String())
			svc := &config.ServiceConfig{Host: host, Port: mustAtoi(t, port), Path: "/app"}
			fc := testFwdCtx()
			fc.Username = "alice"
			fc.SSO = tc.sso

			req := httptest.NewRequest("GET", "/", nil)
			for _, n := range known {
				req.Header.Set(n, tc.clientVal)
			}
			req.Header.Set("X-Custom-User", tc.clientVal)
			rp := NewReverseProxy(svc, fc)
			rec := httptest.NewRecorder()
			rp.ServeHTTP(rec, req)

			for _, n := range known {
				if got[n] != "" {
					t.Fatalf("identity header %s must be stripped, got %q", n, got[n])
				}
			}
			if got["X-Custom-User"] != tc.wantCustom {
				t.Fatalf("X-Custom-User got %q, want %q", got["X-Custom-User"], tc.wantCustom)
			}
		})
	}
}

// An invalid configured header name must be ignored (http.Header.Set would
// panic on it), and no identity header may be set.
func TestSSOInvalidHeaderNameIgnored(t *testing.T) {
	var got string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Bad Header Name")
		w.Write([]byte("ok"))
	}))
	defer backend.Close()
	host, port := splitHostPort(backend.Listener.Addr().String())
	svc := &config.ServiceConfig{Host: host, Port: mustAtoi(t, port), Path: "/app"}
	fc := testFwdCtx()
	fc.Username = "alice"
	fc.SSO = config.SSOState{UserHeader: "Bad Header Name"} // space: not a valid token

	rp := NewReverseProxy(svc, fc)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	if got != "" {
		t.Fatalf("invalid header name must be ignored, got %q", got)
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

// All gateway cookies (session, 2FA pending/setup, route, and future suffixed
// names) must be stripped before a request reaches a backend. The 2FA setup
// cookie in particular carries the plaintext pending TOTP secret.
func TestStripGatewayCookieRemoves2FAAndNamespace(t *testing.T) {
	header := strings.Join([]string{
		auth.SessionCookieName + "=sess",
		auth.TOTACookieName + "=pending",
		auth.TOTASetupCookie + "=setup-secret",
		auth.RouteCookieName + "=/proxy/alice/app",
		auth.RouteCookiePrefix + "abcd1234=/proxy/alice/app",
		"goprox_session_1908=other-instance",
		"goprox_future_cookie=x",
		"app=1",
	}, "; ")

	got := stripGatewayCookie(header)
	if strings.Contains(got, "goprox_") {
		t.Fatalf("gateway cookies leaked to backend: %q", got)
	}
	if got != "app=1" {
		t.Fatalf("non-gateway cookie was lost: %q", got)
	}
}

// A backend must not be able to shadow the gateway's own cookie names when the
// app is served at the root via default_service/Referer (ForwardAsIs), where
// Path=/ is preserved and Set-Cookie would otherwise overwrite the gateway's
// session/route cookies.
func TestForwardAsIsDropsGatewayNamedBackendCookies(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "goprox_session=evil; Path=/; HttpOnly")
		w.Header().Add("Set-Cookie", "goprox_route=evil; Path=/")
		w.Header().Add("Set-Cookie", "sid=ok; Path=/")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer backend.Close()

	host, port := splitHostPort(backend.Listener.Addr().String())
	svc := &config.ServiceConfig{Host: host, Port: mustAtoi(t, port), Path: "/app"}
	req := httptest.NewRequest("GET", "/dashboard", nil)
	fc := BuildProxyForwardContext(req, "alice", "/app", false)
	fc.Mode = ForwardAsIs
	rp := NewReverseProxy(svc, fc)

	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	vals := rec.Result().Header.Values("Set-Cookie")
	if len(vals) != 1 {
		t.Fatalf("Set-Cookie count = %d, want only sid (%v)", len(vals), vals)
	}
	if !strings.Contains(vals[0], "sid=ok") || strings.Contains(vals[0], "goprox_") {
		t.Fatalf("unexpected Set-Cookie: %q", vals[0])
	}
}

// In as-is forwarding the app is mounted at the gateway root, so a backend
// root-absolute redirect must stay at the root; adding /proxy/... would move a
// root-routed SPA under the prefix and break its client-side router.
func TestRewriteLocationForwardAsIsKeepsRootPath(t *testing.T) {
	fc := testFwdCtx()
	fc.Mode = ForwardAsIs

	for _, loc := range []string{"/login", "/docs?x=1"} {
		got, ok := rewriteLocation(loc, "", fc, "127.0.0.1:8888")
		if !ok || got != loc {
			t.Errorf("rewriteLocation(%q) = %q, %v; want unchanged", loc, got, ok)
		}
	}

	got, ok := rewriteLocation("http://127.0.0.1:8888/login", "", fc, "127.0.0.1:8888")
	if !ok || got != "/login" {
		t.Fatalf("absolute backend redirect = %q, %v; want /login", got, ok)
	}
}

// IPv6 backend literals must be bracketed in the URL authority; otherwise the
// outgoing Host/Origin headers are malformed and absolute Location rewriting
// cannot recognize the backend.
func TestBackendAuthorityBracketsIPv6(t *testing.T) {
	cases := []struct {
		host string
		port int
		want string
	}{
		{"127.0.0.1", 8888, "127.0.0.1:8888"},
		{"localhost", 8080, "localhost:8080"},
		{"::1", 8888, "[::1]:8888"},
		{"[::1]", 8888, "[::1]:8888"},
		{"fd00::1", 80, "[fd00::1]:80"},
	}
	for _, c := range cases {
		svc := &config.ServiceConfig{Host: c.host, Port: c.port}
		if got := backendAuthority(svc); got != c.want {
			t.Errorf("backendAuthority(%q, %d) = %q, want %q", c.host, c.port, got, c.want)
		}
	}
}

// backend_path stripping must respect path-segment boundaries and trailing
// slashes; exact file redirects map to the service root and siblings resolve
// under the file's directory.
func TestRewriteLocationBackendPathBoundary(t *testing.T) {
	fc := testFwdCtx()
	cases := []struct {
		loc, backendPath, want string
	}{
		{"/application/x", "/app", "/proxy/alice/jupyter/application/x"},
		{"/app/x", "/app/", "/proxy/alice/jupyter/x"},
		{"/app", "/app", "/proxy/alice/jupyter/"},
		{"/app?x=1", "/app", "/proxy/alice/jupyter/?x=1"},
		{"/app/index.html", "/app/index.html", "/proxy/alice/jupyter/"},
		{"/app/index.html?x=1", "/app/index.html", "/proxy/alice/jupyter/?x=1"},
		{"/app/assets/main.js", "/app/index.html", "/proxy/alice/jupyter/assets/main.js"},
		{"/application", "/app/index.html", "/proxy/alice/jupyter/application"},
	}
	for _, c := range cases {
		got, ok := rewriteLocation(c.loc, c.backendPath, fc, "127.0.0.1:8888")
		if !ok || got != c.want {
			t.Errorf("rewriteLocation(%q, backend_path=%q) = %q, %v; want %q", c.loc, c.backendPath, got, ok, c.want)
		}
	}
}

type closeTrackingBody struct {
	data   []byte
	closed bool
}

func (b *closeTrackingBody) Read(p []byte) (int, error) {
	if len(b.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, b.data)
	b.data = b.data[n:]
	return n, nil
}

func (b *closeTrackingBody) Close() error {
	b.closed = true
	return nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// When an oversize chunked HTML body is streamed through without injection,
// the wrapper must still close the original upstream body so an aborted client
// does not leak the backend connection.
func TestOversizeChunkedHTMLClosesUpstreamBody(t *testing.T) {
	old := maxInjectHTML
	maxInjectHTML = 16
	defer func() { maxInjectHTML = old }()

	body := &closeTrackingBody{data: []byte(strings.Repeat("<p>x</p>", 100))}
	svc := &config.ServiceConfig{Host: "127.0.0.1", Port: 1, Path: "/app"}
	rp := NewReverseProxy(svc, testFwdCtx())
	rp.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			Status:        "200 OK",
			StatusCode:    http.StatusOK,
			Header:        http.Header{"Content-Type": []string{"text/html"}},
			Body:          body,
			ContentLength: -1,
			Request:       req,
		}, nil
	})

	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	if !body.closed {
		t.Fatal("upstream body was not closed after streaming an oversize HTML response")
	}
}

// Client-supplied proxy-metadata headers other than XFF must also be removed
// or overwritten: backends frequently trust X-Real-IP, Forwarded and
// X-Original-URL/X-Rewrite-URL for access control or routing.
func TestForwardedHeadersSanitized(t *testing.T) {
	var got map[string]string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = map[string]string{
			"X-Real-IP":          r.Header.Get("X-Real-IP"),
			"Forwarded":          r.Header.Get("Forwarded"),
			"X-Original-URL":     r.Header.Get("X-Original-URL"),
			"X-Rewrite-URL":      r.Header.Get("X-Rewrite-URL"),
			"X-Forwarded-Port":   r.Header.Get("X-Forwarded-Port"),
			"X-Forwarded-Server": r.Header.Get("X-Forwarded-Server"),
		}
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	host, port := splitHostPort(backend.Listener.Addr().String())
	svc := &config.ServiceConfig{Host: host, Port: mustAtoi(t, port), Path: "/app"}
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.9:4321"
	for k, v := range map[string]string{
		"X-Real-IP":          "10.0.0.1",
		"Forwarded":          "for=10.0.0.1",
		"X-Original-URL":     "/admin",
		"X-Rewrite-URL":      "/admin",
		"X-Forwarded-Port":   "9999",
		"X-Forwarded-Server": "evil",
	} {
		req.Header.Set(k, v)
	}
	fc := BuildProxyForwardContext(req, "alice", "/app", false)
	rp := NewReverseProxy(svc, fc)
	rp.ServeHTTP(httptest.NewRecorder(), req)

	if got["X-Real-IP"] != "203.0.113.9" {
		t.Errorf("X-Real-IP = %q, want peer 203.0.113.9", got["X-Real-IP"])
	}
	for _, h := range []string{"Forwarded", "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-Port", "X-Forwarded-Server"} {
		if got[h] != "" {
			t.Errorf("%s leaked to backend: %q", h, got[h])
		}
	}
}

// X-Forwarded-Prefix describes the mount point: the canonical prefix in path
// mode, but empty for vhost (host root) and as-is (gateway root) forwarding.
func TestForwardedPrefixOnlySetInPrefixMode(t *testing.T) {
	var got string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Forwarded-Prefix")
		w.Write([]byte("ok"))
	}))
	defer backend.Close()
	host, port := splitHostPort(backend.Listener.Addr().String())
	svc := &config.ServiceConfig{Host: host, Port: mustAtoi(t, port), Path: "/app"}

	for _, tc := range []struct {
		name string
		mode ForwardMode
		want string
	}{
		{"prefix", ForwardPrefix, "/proxy/alice/app"},
		{"as-is", ForwardAsIs, ""},
		{"vhost", ForwardVHost, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got = "unset"
			req := httptest.NewRequest("GET", "/dashboard", nil)
			req.Header.Set("X-Forwarded-Prefix", "/attacker")
			fc := BuildProxyForwardContext(req, "alice", "/app", false)
			fc.Mode = tc.mode
			NewReverseProxy(svc, fc).ServeHTTP(httptest.NewRecorder(), req)
			if got != tc.want {
				t.Fatalf("X-Forwarded-Prefix = %q, want %q", got, tc.want)
			}
		})
	}
}

// Origin host comparison must be case-insensitive (browsers normalize it, but
// a client may send mixed-case Host/authority).
func TestOriginAuthorityMatchesCaseInsensitive(t *testing.T) {
	if !originAuthorityMatches("http://GW:30152", "gw:30152") {
		t.Fatal("originAuthorityMatches should ignore host case")
	}
	if originAuthorityMatches("http://other:30152", "gw:30152") {
		t.Fatal("different authorities must not match")
	}
}

// <head> detection must not match <header>; otherwise the base/polyfill is
// injected inside a page header when the document has no <head>.
func TestInjectBaseTagIgnoresHeaderElement(t *testing.T) {
	body := []byte("<html><header>nav</header><body>content</body></html>")
	base := []byte(`<base href="/x/">`)
	out := injectBaseTag(body, base)

	iBase := bytes.Index(out, base)
	iBody := bytes.Index(out, []byte("<body"))
	if iBase < 0 || iBody < 0 {
		t.Fatalf("missing injected base or body: %q", out)
	}
	if iBase > iBody {
		t.Fatalf("base injected after <body>: %q", out)
	}
}
