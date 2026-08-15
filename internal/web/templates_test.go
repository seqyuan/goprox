package web

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/seqyuan/goprox/internal/config"
)

// marshalScriptJSON must produce valid JSON that never closes the surrounding
// <script> element, even for hostile service names/descriptions/categories.
func TestMarshalScriptJSONSafeForScript(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
	}{
		{"control chars", map[string]interface{}{"name": "abc\x01def"}},
		{"script breakout", map[string]interface{}{"name": `x</script><script>alert(1)</script>y`}},
		{"html chars", map[string]interface{}{"name": `<img src=x onerror=alert(1)> & "quoted"`}},
		{"line separators", map[string]interface{}{"name": "a\u2028b\u2029c"}},
		{"chinese", map[string]interface{}{"name": "中文服务"}},
	}
	for _, c := range cases {
		out := marshalScriptJSON(c.in)
		if strings.Contains(out, "</script") {
			t.Errorf("%s: output contains raw </script: %s", c.name, out)
		}
		if strings.Contains(out, "\u2028") || strings.Contains(out, "\u2029") {
			t.Errorf("%s: raw U+2028/29 leaked: %s", c.name, out)
		}
		// The output must still be valid JSON when parsed.
		var v map[string]interface{}
		if err := json.Unmarshal([]byte(out), &v); err != nil {
			t.Errorf("%s: output is not valid JSON (%v): %s", c.name, err, out)
		}
	}
}

// marshalScriptJSON output must decode to the same string values, so the
// dashboard receives the true service name (escapes are JSON-visible only).
func TestMarshalScriptJSONRoundTrip(t *testing.T) {
	want := `x</script><script>alert(1)</script>y`
	out := marshalScriptJSON(map[string]interface{}{"name": want})
	var v map[string]interface{}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatal(err)
	}
	if v["name"] != want {
		t.Fatalf("round trip mismatch: got %q want %q", v["name"], want)
	}
}

// A multi-byte (Chinese) service name must not produce invalid UTF-8 in the
// server-rendered card letter, and the letter must be the first rune.
func TestDashboardCardLetterUsesFirstRune(t *testing.T) {
	svcs := []config.ServiceConfig{
		{ID: "s1", Name: "阿凡达", Host: "127.0.0.1", Port: 1, Path: "/s1"},
		{ID: "s2", Name: "Jupyter", Host: "127.0.0.1", Port: 1, Path: "/s2"},
	}
	page := DashboardPage("GoProx", "alice", svcs, true, false)

	if !utf8.ValidString(page) {
		t.Fatal("dashboard page contains invalid UTF-8")
	}
	if !strings.Contains(page, `data-letter="阿"`) {
		t.Fatalf("expected first-rune letter 阿 for Chinese name, page:\n%s", page)
	}
	if !strings.Contains(page, `data-letter="J"`) {
		t.Fatalf("expected letter J for latin name")
	}
	if strings.Contains(page, "\uFFFD") {
		t.Fatal("replacement character leaked into the dashboard")
	}
}

// The custom site title must appear in the dashboard header <h1> and the
// browser tab title, and must be HTML-escaped against injection.
func TestDashboardPageCustomTitle(t *testing.T) {
	svcs := []config.ServiceConfig{{ID: "s1", Name: "App", Host: "127.0.0.1", Port: 1, Path: "/app"}}
	page := DashboardPage("🧬 生信分析平台", "alice", svcs, true, false)

	if !strings.Contains(page, "<h1>🧬 生信分析平台</h1>") {
		t.Fatal("custom title missing from dashboard header")
	}
	if !strings.Contains(page, "<title>仪表盘 — 🧬 生信分析平台</title>") {
		t.Fatal("custom title missing from browser tab title")
	}

	// Hostile titles must be escaped, not injected into the DOM.
	page = DashboardPage(`x</h1><script>alert(1)</script>`, "alice", svcs, true, false)
	if strings.Contains(page, "</h1><script>") {
		t.Fatal("title not HTML-escaped")
	}
}

// A bwlimit-capped service must render the rate badge server-side, matching
// the client-side re-render.
func TestDashboardPageRateBadge(t *testing.T) {
	svcs := []config.ServiceConfig{
		{ID: "s1", Name: "App", Host: "127.0.0.1", Port: 1, Path: "/app", BWLimit: 10 << 20},
	}
	page := DashboardPage("GoProx", "alice", svcs, true, false)
	if !strings.Contains(page, `class="badge rate"`) || !strings.Contains(page, "限速 10.0 MB/s") {
		t.Fatal("rate badge missing from server-rendered card")
	}
}

// The card icon must try favicon.ico, favicon.svg, and favicon.png in turn
// before falling back to the letter block, so modern apps that serve
// /favicon.svg (like Next.js) still get a real icon.
func TestDashboardCardFaviconCandidates(t *testing.T) {
	svcs := []config.ServiceConfig{
		{ID: "s1", Name: "App", Host: "127.0.0.1", Port: 1, Path: "/app"},
	}
	page := DashboardPage("GoProx", "alice", svcs, true, false)

	for _, want := range []string{
		"/proxy/alice/app/favicon.ico",
		"/proxy/alice/app/favicon.svg",
		"/proxy/alice/app/favicon.png",
		"/proxy/alice/app/favicon-32x32.png",
		"/proxy/alice/app/favicon-16x16.png",
		"data-favs=",
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("dashboard card missing %q\n%s", want, page)
		}
	}
}
