package web

import (
	_ "embed"
	"fmt"
	"html"
	"strings"

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

//go:embed templates/script.js
var dashboardScript string

var faviconSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
  <rect width="32" height="32" rx="6" fill="#3b6ef5"/>
  <path d="M8 10h6v12H8zm10 0h6v8h-6z" fill="#fff" opacity="0.9"/>
  <circle cx="23" cy="22" r="3" fill="#7aa0ff"/>
</svg>`

func PageShell(title, body string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>%s — GoProx</title>
  <style>%s</style>
</head>
<body>
%s
<script>%s</script>
</body>
</html>`, esc(title), baseCSS, body, themeScript)
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

func LoginPage(errorMsg string) string {
	errBlock := ""
	if errorMsg != "" {
		errBlock = fmt.Sprintf(`<p class="error">%s</p>`, esc(errorMsg))
	}
	body := fmt.Sprintf(loginTpl, errBlock)
	return PageShell("登录", body)
}

func DashboardPage(username string, services []config.ServiceConfig, writable bool) string {
	grouped := config.GroupServicesByCategory(services)
	bootJSON := fmt.Sprintf(`{"username":"%s","services":%s,"writable":%t}`,
		esc(username), servicesToJSON(services), writable)

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

	body := fmt.Sprintf(dashboardTpl,
		readOnlyClass,
		hintText,
		categoriesHTML,
		bootJSON,
		dashboardScript,
	)
	return PageShell("仪表盘", body)
}

func NotFoundPage() string {
	body := notFoundTpl
	return PageShell("404", body)
}

func FaviconSVG() string {
	return faviconSVG
}

func servicesToJSON(services []config.ServiceConfig) string {
	if len(services) == 0 {
		return "[]"
	}
	parts := make([]string, 0, len(services))
	for _, s := range services {
		desc := "null"
		if s.Description != "" {
			desc = fmt.Sprintf("%q", s.Description)
		}
		cat := "null"
		if s.Category != "" {
			cat = fmt.Sprintf("%q", s.Category)
		}
		parts = append(parts, fmt.Sprintf(
			`{"id":%q,"name":%q,"description":%s,"host":%q,"port":%d,"path":%q,"websocket":%t,"category":%s,"order":%d}`,
			s.ID, s.Name, desc, s.Host, s.Port, s.Path, s.WebSocket, cat, s.Order,
		))
	}
	return "[" + strings.Join(parts, ",") + "]"
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

	return fmt.Sprintf(`
  <div class="service-card" data-id="%s" data-category="%s">
    %s
    <a class="card-link" href="%s" target="_blank" rel="noopener noreferrer">
      <div class="card-icon">🔗</div>
      <div class="card-body">
        <h2>%s</h2>
        %s
        <div class="card-meta">
          <span class="endpoint">%s:%d</span>
          %s
        </div>
      </div>
    </a>
  </div>`,
		esc(s.ID),
		esc(ternary(s.Category != "", s.Category, "未分类")),
		toolbar,
		esc(proxyURL),
		esc(s.Name),
		desc,
		esc(s.Host), s.Port,
		wsBadge,
	)
}

func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}
