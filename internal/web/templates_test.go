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
	page := DashboardPage("alice", svcs, true)

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

// The card icon must try favicon.ico, favicon.svg, and favicon.png in turn
// before falling back to the letter block, so modern apps that serve
// /favicon.svg (like Next.js) still get a real icon.
func TestDashboardCardFaviconCandidates(t *testing.T) {
	svcs := []config.ServiceConfig{
		{ID: "s1", Name: "App", Host: "127.0.0.1", Port: 1, Path: "/app"},
	}
	page := DashboardPage("alice", svcs, true)

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
