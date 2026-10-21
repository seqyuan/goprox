package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/seqyuan/goprox/internal/config"
)

func vhostFwdCtx(req *http.Request, servicePath, requestPath string) ProxyForwardContext {
	fc := BuildProxyForwardContext(req, "alice", servicePath, false)
	fc.Mode = ForwardVHost
	fc.Base = BaseForPath("", requestPath)
	return fc
}

func TestRewriteLocationVHostKeepsRootPath(t *testing.T) {
	fc := testFwdCtx()
	fc.Mode = ForwardVHost
	got, ok := rewriteLocation("/docs?x=1", "", fc, "127.0.0.1:8888")
	if !ok || got != "/docs?x=1" {
		t.Fatalf("got %q ok=%v, want /docs?x=1", got, ok)
	}
}

func TestRewriteLocationVHostAbsoluteBackendURL(t *testing.T) {
	fc := testFwdCtx()
	fc.Mode = ForwardVHost
	got, ok := rewriteLocation("http://127.0.0.1:8888/docs", "", fc, "127.0.0.1:8888")
	if !ok || got != "/docs" {
		t.Fatalf("got %q ok=%v, want /docs", got, ok)
	}
}

func TestProxyVHostBaseAndCookieHandling(t *testing.T) {
	var gotPrefix string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPrefix = r.Header.Get("X-Forwarded-Prefix")
		w.Header().Add("Set-Cookie", "sid=abc; Path=/; Secure; HttpOnly")
		w.Header().Add("Set-Cookie", "goprox_session=evil; Path=/; Secure")
		w.Header().Add("Set-Cookie", "goprox_route=evil; Path=/")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte("<html><head><title>x</title></head><body>ok</body></html>"))
	}))
	defer backend.Close()

	host, port := splitHostPort(backend.Listener.Addr().String())
	svc := &config.ServiceConfig{Host: host, Port: mustAtoi(t, port), Path: "/hugo"}
	req := httptest.NewRequest("GET", "/docs/", nil)
	fc := vhostFwdCtx(req, "/hugo", "/docs/")
	rp := NewReverseProxy(svc, fc)

	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	if gotPrefix != "" {
		t.Fatalf("X-Forwarded-Prefix = %q, want empty in vhost mode", gotPrefix)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `<base href="/docs/">`) {
		t.Fatalf("missing vhost base in %q", body)
	}

	vals := rec.Result().Header.Values("Set-Cookie")
	if len(vals) != 1 {
		t.Fatalf("Set-Cookie count = %d, want 1 (%v)", len(vals), vals)
	}
	c := parseCookie(t, vals[0])
	if c.Name != "sid" || c.Path != "/" || c.Secure {
		t.Fatalf("vhost cookie = Name:%q Path:%q Secure:%v; want sid, /, false", c.Name, c.Path, c.Secure)
	}
}
