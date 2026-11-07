package server

// 访问/登录事件记录与状态码捕获：给「日志页」提供每用户的历史，给「测一下」提供结果。

import (
	"bufio"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/seqyuan/goprox/internal/config"
	"github.com/seqyuan/goprox/internal/eventlog"
)

// recordLogin stores a sign-in attempt. Only existing accounts are recorded:
// an attacker trying random usernames must not be able to grow the per-user map
// without bound.
func (s *Server) recordLogin(username string, ok bool, detail string) {
	if s.events == nil || !config.IsValidUsername(username) {
		return
	}
	if s.registry.GetUserConfigForLogin(username) == nil {
		return
	}
	s.events.Add(username, eventlog.Event{Kind: eventlog.KindLogin, OK: ok, Detail: detail})
}

// recordAccess stores one card access. failure carries the proxy's error text
// (empty on success); status is used for locally served cards (files), where no
// proxy error handler exists.
func (s *Server) recordAccess(username string, svc *config.ServiceConfig, r *http.Request, originalPath string, status int, d time.Duration, failure string) {
	if s.events == nil || username == "" || svc == nil || !loggableRequest(r) {
		return
	}
	// originalPath is the browser-visible URI (the proxy rewrites r.URL.Path to
	// the backend path, which would be useless in the history).
	target := originalPath
	if target == "" {
		target = r.URL.RequestURI()
	}
	ev := eventlog.Event{
		Kind:    eventlog.KindAccess,
		OK:      failure == "" && status < http.StatusBadRequest,
		Service: svc.Name,
		Detail:  r.Method + " " + target,
		Millis:  d.Milliseconds(),
	}
	if failure != "" {
		ev.Detail = failure
	} else if status >= http.StatusBadRequest {
		ev.Detail = http.StatusText(status)
	}
	s.events.Add(username, ev)
}

// loggableRequest drops static subresources: a single page load fetches dozens
// of JS/CSS/images, and recording them would bury the meaningful entries (and
// rotate them out of the fixed-size history within seconds).
func loggableRequest(r *http.Request) bool {
	switch r.Method {
	case http.MethodHead, http.MethodOptions:
		return false
	}
	p := strings.ToLower(r.URL.Path)
	for _, ext := range []string{
		".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
		".avif", ".ico", ".bmp", ".woff", ".woff2", ".ttf", ".otf", ".map",
		".wasm", ".mp4", ".webm", ".mp3", ".wav", ".ogg", ".pdf", ".zip",
	} {
		if strings.HasSuffix(p, ext) {
			return false
		}
	}
	for _, root := range []string{"/_next/", "/_nuxt/", "/static/", "/assets/", "/favicon."} {
		if strings.Contains(p, root) {
			return false
		}
	}
	return true
}

// statusRecorder captures the status code of a locally served response. It
// passes through the optional interfaces an HTTP handler may rely on
// (Flusher/Hijacker/Pusher/ReaderFrom) so wrapping never changes behavior.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

func (r *statusRecorder) statusCode() int {
	if r.status == 0 {
		return http.StatusOK
	}
	return r.status
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := r.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

func (r *statusRecorder) Push(target string, opts *http.PushOptions) error {
	if p, ok := r.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}
