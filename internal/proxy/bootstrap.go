package proxy

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/seqyuan/goprox/internal/config"
)

// shouldBootstrap reports whether an unauthenticated backend response should be
// turned into a browser-visible redirect carrying the session-bootstrap token.
//
// The guard is deliberately narrow so it can never loop or hijack a real API
// error:
//   - only 401/403 (an unauthenticated page),
//   - only GET navigations that ask for HTML (Accept: text/html),
//   - a mode with a deterministic path (canonical /proxy/, vhost, or as-is
//     forwarding), and for canonical mode the path must look like /proxy/,
//   - never when the request already carried the token param (so a rejected
//     token degrades to the backend's own response instead of a redirect loop).
func shouldBootstrap(resp *http.Response, fc ProxyForwardContext) bool {
	if fc.Bootstrap == nil || fc.OriginalPath == "" {
		return false
	}
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		return false
	}
	req := resp.Request
	if req == nil || req.Method != http.MethodGet {
		return false
	}
	if !strings.Contains(strings.ToLower(req.Header.Get("Accept")), "text/html") {
		return false
	}
	if fc.Mode == ForwardPrefix && !strings.HasPrefix(fc.OriginalPath, "/proxy/") {
		return false
	}
	if req.URL.Query().Get(bootstrapParam(fc.Bootstrap)) != "" {
		return false
	}
	return true
}

// bootstrapParam returns the configured query-param name, defaulting to "token".
func bootstrapParam(b *config.AuthBootstrapConfig) string {
	if b != nil {
		if p := strings.TrimSpace(b.Param); p != "" {
			return p
		}
	}
	return "token"
}

// addBootstrapParam appends the token to the browser-visible path/query.
func addBootstrapParam(originalPath, param, token string) string {
	if param == "" {
		param = "token"
	}
	sep := "?"
	if strings.Contains(originalPath, "?") {
		sep = "&"
	}
	return originalPath + sep + url.QueryEscape(param) + "=" + url.QueryEscape(token)
}

// bootstrapToken resolves the backend session-bootstrap token from the service's
// auth_bootstrap config. It is called only when a page request came back
// unauthenticated, so the uncached read also picks up a token rotation after the
// backend restarts.
func bootstrapToken(b *config.AuthBootstrapConfig) (string, bool) {
	if b == nil {
		return "", false
	}
	switch b.Mode {
	case config.BootstrapModeStatic:
		v := strings.TrimSpace(b.TokenValue)
		return v, v != ""
	case config.BootstrapModeFile:
		data, err := os.ReadFile(b.TokenFile)
		if err != nil {
			return "", false
		}
		return extractToken(string(data), b.TokenRegex)
	case config.BootstrapModeLog:
		data, err := readFileTail(b.TokenLog, 64<<10)
		if err != nil {
			return "", false
		}
		return extractToken(data, b.TokenRegex)
	}
	return "", false
}

// extractToken returns the token from free-form text. With a regex it returns
// the last match (capture group 1 when present, else the whole match), so a
// restarted backend's newest token wins over older lines in an append-only log.
// Without a regex the text is treated as a single value; if it has several
// lines, the last non-empty one wins.
func extractToken(text, pattern string) (string, bool) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		lines := strings.Split(text, "\n")
		for i := len(lines) - 1; i >= 0; i-- {
			if v := strings.TrimSpace(lines[i]); v != "" {
				return v, true
			}
		}
		return "", false
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", false
	}
	matches := re.FindAllStringSubmatch(text, -1)
	if len(matches) == 0 {
		return "", false
	}
	last := matches[len(matches)-1]
	if len(last) > 1 && last[1] != "" {
		return last[1], true
	}
	return last[0], true
}

// readFileTail reads up to max bytes from the end of path, so a large,
// append-only log can be scanned without loading the whole file.
func readFileTail(path string, max int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if info.Size() > max {
		if _, err := f.Seek(info.Size()-max, io.SeekStart); err != nil {
			return "", err
		}
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
