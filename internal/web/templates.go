package web

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"html"
	"strings"
	"unicode/utf8"

	"github.com/seqyuan/goprox/internal/config"
)

//go:embed templates/base.css
var baseCSS string

//go:embed templates/login.html
var loginTpl string

//go:embed templates/dashboard.html
var dashboardTpl string

//go:embed templates/notfound.html
var notFoundTpl string

//go:embed templates/twofa.html
var twofaTpl string

//go:embed templates/twofa_setup.html
var twofaSetupTpl string

//go:embed templates/script.js
var dashboardScript string

var faviconSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
  <rect width="32" height="32" rx="6" fill="#3b6ef5"/>
  <path d="M8 10h6v12H8zm10 0h6v8h-6z" fill="#fff" opacity="0.9"/>
  <circle cx="23" cy="22" r="3" fill="#7aa0ff"/>
</svg>`

func PageShell(siteTitle, title, body string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>%s — %s</title>
  <style>%s</style>
</head>
<body>
%s
<script>%s</script>
</body>
</html>`, esc(title), esc(siteTitle), baseCSS, body, themeScript)
}

const themeScript = `
(function() {
  var key = 'goprox-theme';
  function apply(t) {
    document.documentElement.classList.toggle('dark', t === 'dark');
    var btn = document.getElementById('theme-toggle');
    if (btn) btn.textContent = t === 'dark' ? '☀️' : '🌙';
  }
  var saved = localStorage.getItem(key);
  if (saved === 'dark' || saved === 'light') apply(saved);
  else apply(window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  window.toggleTheme = function() {
    var next = document.documentElement.classList.contains('dark') ? 'light' : 'dark';
    localStorage.setItem(key, next);
    apply(next);
  };
})();`

func esc(s string) string {
	return html.EscapeString(s)
}

func LoginPage(siteTitle, errorMsg, next string) string {
	errBlock := ""
	if errorMsg != "" {
		errBlock = fmt.Sprintf(`<p class="error">%s</p>`, esc(errorMsg))
	}
	body := fmt.Sprintf(loginTpl, esc(siteTitle), errBlock, esc(next))
	return PageShell(siteTitle, "登录", body)
}

func DashboardPage(siteTitle, username string, services []config.ServiceConfig, writable, twoFAEnabled bool) string {
	grouped := config.GroupServicesByCategory(services)
	bootJSON := marshalScriptJSON(dashboardBoot{
		Username: username,
		Services: services,
		Writable: writable,
	})

	categoriesHTML := renderCategories(grouped, username, writable)
	if categoriesHTML == "" {
		categoriesHTML = `<p class="empty">暂无服务。点击顶部 + 添加转发。</p>`
	}

	hintText := ""
	readOnlyClass := ""
	if writable {
		hintText = "点击卡片访问服务；拖动卡片调整顺序与分类，点击顶部 + 添加。"
	} else {
		hintText = "当前配置不可由网关写入。请执行 <code>goprox passwd</code> 修复权限。"
		readOnlyClass = " read-only"
	}

	// Two-factor status + management link (hint text is rendered as HTML).
	if twoFAEnabled {
		hintText += ` 两步验证已开启 · <a href="/2fa/setup">管理</a>`
	} else {
		hintText += ` 两步验证未开启 · <a href="/2fa/setup">开启</a>`
	}

	body := fmt.Sprintf(dashboardTpl,
		esc(siteTitle),
		readOnlyClass,
		hintText,
		categoriesHTML,
		bootJSON,
		dashboardScript,
	)
	return PageShell(siteTitle, "仪表盘", body)
}

func NotFoundPage(siteTitle string) string {
	body := notFoundTpl
	return PageShell(siteTitle, "404", body)
}

// TwoFAPage renders the second login step: enter the 6-digit TOTP code.
func TwoFAPage(siteTitle, errorMsg, next string) string {
	errBlock := ""
	if errorMsg != "" {
		errBlock = fmt.Sprintf(`<p class="error">%s</p>`, esc(errorMsg))
	}
	body := fmt.Sprintf(twofaTpl, errBlock, esc(next))
	return PageShell(siteTitle, "两步验证", body)
}

// TwoFASetupPage renders the enrollment page: QR code + secret + verify form.
// When 2FA is already enabled it also shows a disable form.
func TwoFASetupPage(siteTitle, errorMsg, secret string, enabled bool) string {
	errBlock := ""
	if errorMsg != "" {
		errBlock = fmt.Sprintf(`<p class="error">%s</p>`, esc(errorMsg))
	}
	disableBlock := ""
	if enabled {
		disableBlock = `<form method="POST" action="/2fa/disable"><button type="submit" class="cancel-link" style="border:none;background:none;cursor:pointer;margin:0 auto">关闭两步验证</button></form>`
	}
	body := fmt.Sprintf(twofaSetupTpl, errBlock, esc(secret), disableBlock)
	return PageShell(siteTitle, "设置两步验证", body)
}

func FaviconSVG() string {
	return faviconSVG
}

// dashboardBoot is the JSON object embedded as window.__GOPROX_BOOT__.
type dashboardBoot struct {
	Username string                 `json:"username"`
	Services []config.ServiceConfig `json:"services"`
	Writable bool                   `json:"writable"`
}

// marshalScriptJSON serializes v as JSON that is safe to inline inside a
// <script> element. json.Marshal escapes quotes/backslashes/control chars
// correctly, and the extra escaping of "<", ">", "&" and U+2028/U+2029
// prevents untrusted strings (service names, descriptions, categories) from
// closing the script tag or breaking older JS parsers.
func marshalScriptJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	s := string(b)
	s = strings.ReplaceAll(s, "<", `\u003c`)
	s = strings.ReplaceAll(s, ">", `\u003e`)
	s = strings.ReplaceAll(s, "&", `\u0026`)
	s = strings.ReplaceAll(s, "\u2028", `\u2028`)
	s = strings.ReplaceAll(s, "\u2029", `\u2029`)
	return s
}

func renderCategories(groups []config.GroupedServices, username string, writable bool) string {
	if len(groups) == 0 {
		return ""
	}
	blocks := make([]string, 0, len(groups))
	for _, g := range groups {
		cards := make([]string, 0, len(g.Services))
		for _, s := range g.Services {
			cards = append(cards, renderCard(s, username, writable))
		}
		blocks = append(blocks, fmt.Sprintf(`
    <section class="category-block" data-category="%s">
      <h2 class="category-title">%s</h2>
      <div class="card-grid" data-drop-zone>%s</div>
    </section>`, esc(g.Category), esc(g.Category), strings.Join(cards, "")))
	}
	return strings.Join(blocks, "")
}

func renderCard(s config.ServiceConfig, username string, writable bool) string {
	proxyURL := fmt.Sprintf("/proxy/%s%s/", username, s.Path)
	desc := ""
	if s.Description != "" {
		desc = fmt.Sprintf(`<p class="card-desc">%s</p>`, esc(s.Description))
	}
	wsBadge := ""
	if s.WebSocket {
		wsBadge = `<span class="badge ws">WebSocket</span>`
	}
	rateBadge := ""
	if s.BWLimit > 0 {
		rateBadge = fmt.Sprintf(`<span class="badge rate">限速 %s</span>`, fmtRate(s.BWLimit))
	}

	toolbar := ""
	if writable {
		toolbar = fmt.Sprintf(`<div class="card-toolbar">
        <span class="drag-handle" draggable="true" data-drag-handle="1" title="拖动排序">⋮⋮</span>
        <div class="card-actions">
          <button type="button" class="card-edit" data-edit-id="%s" title="编辑">✎</button>
          <button type="button" class="card-delete" data-delete-id="%s" title="删除">×</button>
        </div>
      </div>`, esc(s.ID), esc(s.ID))
	}

	firstChar := "?"
	// Decode the first rune, not the first byte: slicing s.Name[:1] on a
	// multi-byte name (Chinese, emoji) would yield invalid UTF-8.
	if r, size := utf8.DecodeRuneInString(s.Name); size > 0 && r != utf8.RuneError {
		firstChar = strings.ToUpper(string(r))
	}

	faviconHTML := renderFavicon(username, s.Path, firstChar)

	return fmt.Sprintf(`
  <div class="service-card" data-id="%s" data-category="%s">
    %s
    <a class="card-link" href="%s" target="_blank" rel="noopener noreferrer">
      <div class="card-icon">%s</div>
      <div class="card-body">
        <h2>%s</h2>
        %s
        <div class="card-meta">
          <span class="endpoint">%s:%d</span>
          %s
          %s
        </div>
      </div>
    </a>
  </div>`,
		esc(s.ID),
		esc(ternary(s.Category != "", s.Category, "未分类")),
		toolbar,
		esc(proxyURL),
		faviconHTML,
		esc(s.Name),
		desc,
		esc(s.Host), s.Port,
		wsBadge,
		rateBadge,
	)
}

// fmtRate renders a bytes-per-second cap in human-readable units.
func fmtRate(b int64) string {
	const (
		gb = int64(1) << 30
		mb = int64(1) << 20
		kb = int64(1) << 10
	)
	switch {
	case b >= gb:
		return fmt.Sprintf("%.1f GB/s", float64(b)/float64(gb))
	case b >= mb:
		return fmt.Sprintf("%.1f MB/s", float64(b)/float64(mb))
	case b >= kb:
		return fmt.Sprintf("%d KB/s", b/kb)
	default:
		return fmt.Sprintf("%d B/s", b)
	}
}

// faviconOnError advances through the candidate favicon URLs (data-favs,
// space-separated) until one loads; when exhausted it hides the <img> and
// reveals the first-letter block (its next sibling).
const faviconOnError = "var e=this,l=e.getAttribute('data-favs').split(' '),i=+(e.getAttribute('data-fav-idx')||0)+1;if(i<l.length){e.setAttribute('data-fav-idx',i);e.src=l[i];}else{e.style.display='none';e.nextElementSibling.style.display='flex';}"

// renderFavicon builds the card icon: it tries the most common favicon
// locations in turn (favicon.ico, favicon.svg, favicon.png, and the
// -32x32/-16x16 PNG variants used by static-site generators) before falling
// back to the colored first-letter block. This covers modern apps that serve
// /favicon.svg or sized PNGs instead of the legacy .ico.
func renderFavicon(username, servicePath, firstChar string) string {
	base := fmt.Sprintf("/proxy/%s%s", username, servicePath)
	favs := []string{
		base + "/favicon.ico",
		base + "/favicon.svg",
		base + "/favicon.png",
		base + "/favicon-32x32.png",
		base + "/favicon-16x16.png",
	}
	return fmt.Sprintf(`<img src="%s" data-favs="%s" data-fav-idx="0" onerror="%s" alt=""><span class="card-letter" data-letter="%s">%s</span>`,
		esc(favs[0]), esc(strings.Join(favs, " ")), faviconOnError, esc(firstChar), firstChar)
}

func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}
