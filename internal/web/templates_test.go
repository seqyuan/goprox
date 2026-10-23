package web

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
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
	page := DashboardPage("GoProx", "alice", svcs, true, false, "", "")

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
	page := DashboardPage("🧬 生信分析平台", "alice", svcs, true, false, "", "")

	if !strings.Contains(page, "<h1>🧬 生信分析平台</h1>") {
		t.Fatal("custom title missing from dashboard header")
	}
	if !strings.Contains(page, "<title>仪表盘 — 🧬 生信分析平台</title>") {
		t.Fatal("custom title missing from browser tab title")
	}

	// Hostile titles must be escaped, not injected into the DOM.
	page = DashboardPage(`x</h1><script>alert(1)</script>`, "alice", svcs, true, false, "", "")
	if strings.Contains(page, "</h1><script>") {
		t.Fatal("title not HTML-escaped")
	}
}

// Cards hide the backend address, bandwidth cap, and the WebSocket badge so
// each card stays one compact row. Those values stay in the boot JSON so the
// edit form can still load them.
func TestDashboardPageHidesEndpointAndRate(t *testing.T) {
	svcs := []config.ServiceConfig{
		{ID: "s1", Name: "App", Host: "127.0.0.1", Port: 18080, Path: "/app", BWLimit: 10 << 20},
		{ID: "s2", Name: "Tunnel", Host: "10.1.2.3", Port: 9, Path: "/tunnel", WebSocket: true},
	}
	page := DashboardPage("GoProx", "alice", svcs, true, false, "", "")

	dashStart := strings.Index(page, `<div id="dashboard">`)
	dashEnd := strings.Index(page, `</main>`)
	if dashStart < 0 || dashEnd < dashStart {
		t.Fatal("dashboard markup missing")
	}
	cards := page[dashStart:dashEnd]
	for _, forbidden := range []string{
		`class="endpoint"`, `class="badge rate"`, `class="card-meta"`, `class="badge ws"`,
		"限速", "WebSocket", "127.0.0.1:18080", "10.1.2.3:9",
	} {
		if strings.Contains(cards, forbidden) {
			t.Fatalf("card HTML still shows %q", forbidden)
		}
	}

	bootStart := strings.Index(page, "window.__GOPROX_BOOT__ = ")
	if bootStart < 0 {
		t.Fatal("boot JSON missing")
	}
	bootEnd := strings.Index(page[bootStart:], "</script>")
	if bootEnd < 0 {
		t.Fatal("boot JSON closing tag missing")
	}
	bootEnd += bootStart
	boot := page[bootStart:bootEnd]
	for _, want := range []string{`"host":"127.0.0.1"`, `"port":18080`, `"bwlimit":10485760`, `"host":"10.1.2.3"`, `"websocket":true`} {
		if !strings.Contains(boot, want) {
			t.Fatalf("boot JSON missing %q", want)
		}
	}

	// Client re-render must match: the embedded script no longer paints
	// address, rate, or the WebSocket badge.
	script := page[bootEnd:]
	for _, forbidden := range []string{`class="endpoint"`, `class="badge rate"`, `class="card-meta"`, `class="badge ws"`, "限速 "} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("client render still includes %q", forbidden)
		}
	}
}

// Everyday dashboard chrome: no standing tutorial, account menu for 2FA,
// search, collapsed advanced fields, and reorder controls.
func TestDashboardUXChrome(t *testing.T) {
	svcs := []config.ServiceConfig{
		{ID: "jupyter", Name: "Jupyter", Description: "notebook", Host: "127.0.0.1", Port: 8888, Path: "/jupyter", Category: "分析", Order: 0, WebSocket: true, BWLimit: 10 << 20},
		{ID: "rstudio", Name: "RStudio", Host: "127.0.0.1", Port: 8787, Path: "/rstudio", Category: "分析", Order: 1, WebSocket: true},
		{ID: "grafana", Name: "Grafana", Host: "127.0.0.1", Port: 3000, Path: "/grafana", Category: "监控", Order: 2},
	}
	page := DashboardPage("GoProx", "alice", svcs, true, false, "", "")

	for _, gone := range []string{"点击卡片访问服务", "拖动卡片", "两步验证未开启", "字节/秒", "10485760 = 10", `step="0.1"`} {
		if strings.Contains(page, gone) {
			t.Fatalf("standing tutorial or raw byte field still present: %q", gone)
		}
	}
	if strings.Contains(page, "0.08em") {
		t.Fatal("category title still uses wide letter-spacing")
	}
	for _, want := range []string{
		`id="account-toggle"`,
		">alice</button>",
		`href="/2fa/setup">开启两步验证</a>`,
		`id="service-search"`,
		`没有匹配的服务`,
		`data-jump="分析"`,
		`data-jump="监控"`,
		`id="add-advanced"`,
		`id="edit-advanced"`,
		`list="category-options"`,
		`MB/s，留空不限速`,
		// step="any": step="0.1" rejected saved caps like 9.537 (bwlimit
		// 10000000) and blocked the whole form from submitting.
		`type="number" min="0" step="any"`,
		`data-busy-label="正在添加"`,
		// Toast must sit below the modal backdrop (30).
		`z-index: 25`,
		`hover: hover`,
		`data-move="up"`,
		`data-move="down"`,
		`if (after === card) return;`,
		"这只删除转发入口",
		"正在保存",
		"1048576",
		`ev.key === "/"`,
		// Default category is a single source of truth: Go constant -> boot JSON.
		`"defaultCategory":"未分类"`,
		// Pure client helpers are embedded and exposed for the shared tests.
		"window.GoProx",
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("dashboard missing %q", want)
		}
	}

	// First card in a category cannot move up; the last cannot move down.
	upJupyter := `data-move="up" data-move-id="jupyter" title="上移" aria-label="上移" disabled`
	downRStudio := `data-move="down" data-move-id="rstudio" title="下移" aria-label="下移" disabled`
	if !strings.Contains(page, upJupyter) {
		t.Fatal("first card in a category should disable 上移")
	}
	if !strings.Contains(page, downRStudio) {
		t.Fatal("last card in a category should disable 下移")
	}

	readonly := DashboardPage("GoProx", "alice", svcs, false, true, "", "")
	if !strings.Contains(readonly, "goprox passwd") {
		t.Fatal("read-only hint missing")
	}
	if !strings.Contains(readonly, `href="/2fa/setup">两步验证已开启</a>`) {
		t.Fatal("enabled 2FA link missing from account menu")
	}
	hintStart := strings.Index(readonly, `id="dashboard-hint"`)
	if hintStart < 0 {
		t.Fatal("read-only hint element missing")
	}
	hintEnd := strings.Index(readonly[hintStart:], "</p>")
	if hintEnd < 0 {
		t.Fatal("read-only hint element not closed")
	}
	hint := readonly[hintStart : hintStart+hintEnd]
	if strings.Contains(hint, "两步验证") {
		t.Fatal("2FA status should live in the account menu, not the hint")
	}

	empty := DashboardPage("GoProx", "alice", nil, true, false, "", "")
	if !strings.Contains(empty, "点击右上角 + 添加") {
		t.Fatal("empty writable dashboard should explain how to add a service")
	}
	if !strings.Contains(empty, `id="service-search" class="service-search" type="search" placeholder="搜索名称或说明" autocomplete="off" aria-label="搜索服务" hidden`) {
		t.Fatal("search box should be hidden when there are no services")
	}
}

// Wide windows get more card columns. The cap is the content width; the grid
// itself stays auto-fill, so the saved order does not depend on column count.
func TestDashboardGridWidensOnLargeScreens(t *testing.T) {
	page := DashboardPage("GoProx", "alice", nil, true, false, "", "")
	if !strings.Contains(page, "--max-grid: 1680px") {
		t.Fatal("dashboard content width is not wide enough for 5 columns")
	}
	if !strings.Contains(page, "repeat(auto-fill, minmax(280px, 1fr))") {
		t.Fatal("card grid is not auto-fill")
	}
}

// The client utility module (util.js) must stay in lockstep with the Go
// implementation. We generate slugify cases from config.SlugifyName and hand
// them to the Node test, so a change to either side breaks this test.
func TestDashboardUtilSlugParity(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; skipping JS util tests")
	}

	inputs := []string{
		"Jupyter",
		"My App",
		"数据分析平台",
		"  R Studio!  ",
		"",
		"a.b_c~d",
		"a__b--c",
		"---",
		"Ünïcødé",
		"a/b\\c:d",
	}
	cases := make([]map[string]string, 0, len(inputs))
	for _, in := range inputs {
		cases = append(cases, map[string]string{"name": in, "slug": config.SlugifyName(in)})
	}
	raw, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	casesFile := filepath.Join(t.TempDir(), "slug_cases.json")
	if err := os.WriteFile(casesFile, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(node, "--test", filepath.Join("templates", "util_test.js"))
	cmd.Env = append(os.Environ(), "GOPROX_SLUG_CASES="+casesFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node util tests failed: %v\n%s", err, out)
	}
}

// The card icon must try favicon.ico, favicon.svg, and favicon.png in turn
// before falling back to the letter block, so modern apps that serve
// /favicon.svg (like Next.js) still get a real icon.
func TestDashboardCardFaviconCandidates(t *testing.T) {
	svcs := []config.ServiceConfig{
		{ID: "s1", Name: "App", Host: "127.0.0.1", Port: 1, Path: "/app"},
	}
	page := DashboardPage("GoProx", "alice", svcs, true, false, "", "")

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

func TestDashboardVHostLink(t *testing.T) {
	svcs := []config.ServiceConfig{{
		ID: "hugo", Name: "Hugo", Host: "127.0.0.1", Port: 1313, Path: "/hugo",
		Hostnames: []string{"hugo.gw.example.test"},
	}}
	page := DashboardPage("GoProx", "alice", svcs, true, false, "https", "gw.example.test:30152")
	htmlPart := page
	if i := strings.Index(htmlPart, "<script>window.__GOPROX_BOOT__"); i >= 0 {
		htmlPart = htmlPart[:i]
	}
	for _, want := range []string{
		`class="card-vhost"`,
		`href="https://hugo.gw.example.test:30152/"`,
	} {
		if !strings.Contains(htmlPart, want) {
			t.Fatalf("vhost link missing %q", want)
		}
	}
}

func TestDashboardNoVHostLinkWithoutHostnames(t *testing.T) {
	svcs := []config.ServiceConfig{{
		ID: "app", Name: "App", Host: "127.0.0.1", Port: 8080, Path: "/app",
	}}
	page := DashboardPage("GoProx", "alice", svcs, true, false, "https", "gw.example.test")
	htmlPart := page
	if i := strings.Index(htmlPart, "<script>window.__GOPROX_BOOT__"); i >= 0 {
		htmlPart = htmlPart[:i]
	}
	if strings.Contains(htmlPart, `class="card-vhost"`) {
		t.Fatal("card-vhost must not be rendered without hostnames")
	}
}

// A service mounted at "/" must not produce double slashes in card links or
// favicon URLs; ServeMux would redirect them and the base href would be odd.
func TestDashboardRootServiceNoDoubleSlash(t *testing.T) {
	svcs := []config.ServiceConfig{{
		ID: "root", Name: "Root", Host: "127.0.0.1", Port: 1, Path: "/",
	}}
	page := DashboardPage("GoProx", "alice", svcs, true, false, "", "")
	if strings.Contains(page, "/proxy/alice//") {
		t.Fatalf("root service produced a double slash: %s", page)
	}
	if !strings.Contains(page, `href="/proxy/alice/"`) {
		t.Fatal("root service card link missing /proxy/alice/")
	}
	if !strings.Contains(page, "/proxy/alice/favicon.ico") {
		t.Fatal("root service favicon URL missing")
	}
}

// Logout is a POST; the GET page is only a confirmation and must not perform
// any state change itself.
func TestLogoutConfirmPageUsesPost(t *testing.T) {
	page := LogoutConfirmPage("GoProx")
	if !strings.Contains(page, `method="POST"`) || !strings.Contains(page, `action="/logout"`) {
		t.Fatalf("logout confirmation page missing POST form: %s", page)
	}
}
