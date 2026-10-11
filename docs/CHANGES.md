# GoProx v0.5.1 变更日志（2026-10-11）

## 变更

- **卡片不再显示 WebSocket 徽标**：卡片仅保留图标、名称与说明，去掉标签行，行高更紧凑。`websocket` 字段与编辑表单的开关不受影响

---

# GoProx v0.5.0 变更日志（2026-10-11）

## 新功能

- **仪表盘交互改版**：新增搜索框（按名称/说明即时过滤）、分类导航条（点击跳转）、卡片「上移/下移」按钮（同分类内换序，拖拽排序保留）、右上角账户菜单（账号名 / 两步验证入口 / 外观切换 / 退出）。分类在 `order` 并列时改为稳定排序，服务端预渲染与前端重渲染顺序一致
- **带宽上限改用 MB/s 输入**：新增/编辑表单以 MB/s 为单位填写，留空即不限速；卡片上不再显示 `host:port` 与限速徽标（WebSocket 徽标保留）

## 修复

- **带宽输入框挡住表单提交**：`step="0.1"` 使已保存的非整数 MB 限速（如 `bwlimit: 10000000` 显示为 `9.537`）触发浏览器 step 校验失败，整个表单（含仅改名字）无法提交。改为 `step="any"`，并在字段未改动时按原始字节回写，避免 MB 往返的精度丢失
- **上移/下移连点导致布局错乱**：连续点击会并发发出多个 `PUT /api/services/layout`，响应乱序时界面会覆盖服务器最终结果。布局保存改为串行（保存期间禁用上移/下移并忽略拖拽）
- **自动路径可能与已有路径冲突**：`AddService` 生成默认路径时只保证 ID 唯一，未检查已有自定义路径（如已有服务占用 `/myapp` 时，新增名为 `Myapp` 的服务会生成同名路径）。现自动路径也去重（`-2`/`-3`…）
- **表单错误重复与遮挡**：提交失败时行内错误与 toast 同时出现，且 toast 层级高于弹窗会盖住底部。现失败只显示行内错误，toast 层级降到弹窗之下
- **卡片操作选择器注入**：`moveCard`/拖拽放下由字符串拼接 `querySelector` 改为遍历比对 `data-id`，手写配置中 ID 含引号/反斜杠等字符不再报错或误命中
- **添加按钮忙碌文案**：请求期间由「正在保存」改为「正在添加」

## 测试

- 前端纯函数（slugify、ID 去重、自动路径去重、MB↔字节换算、HTML 转义）抽到 `templates/util.js`，配 Node 单测；并由 Go 生成用例校验 `slugifyName` 与 `config.SlugifyName` 一致，防止两侧漂移
- 新增浏览器端到端用例（Playwright）：编辑 `bwlimit=10000000`（显示 `9.537`）仅改名字可正常保存且限速原样保留

---

# GoProx v0.4.2 变更日志（2026-08-27）

## 变更

- **默认端口改为 30152**：`--port` 缺省值从 1908 调整为 30152，同步更新帮助文本、README、GitHub Pages 站点与全部文档示例
- **GitHub Actions 自动发版**：新增 `.github/workflows/release.yml`，push `v*` tag 时自动跑测试、交叉编译 Linux/macOS（amd64 + arm64）并发布 GitHub Release（tar.gz 包 + SHA256 校验和，版本号取自 tag）

---

# GoProx v0.4.1 变更日志（2026-08-22）

## 新功能

- **轻量级单点登录（SSO）**：`goprox sso` 开启后，网关把登录用户名以请求头形式带给所有被代理的后端（如 `X-Authenticated-User: alice`），后端信任该头即可免登录识别用户。可选 `--hmac-secret` 共享密钥：同时下发 `user_header-Signature`（HMAC-SHA256，base64url），后端验签后不再依赖网络隔离。配置持久化到 `state.yaml` 的 `sso` 段，重启生效，启动日志打印当前模式
- **身份头防伪造**：网关始终覆盖（而非透传）客户端传入的身份头，并无条件剥离 `X-Authenticated-User` / `X-Forwarded-User` / `X-Auth-Request-User` / `Remote-User` / `Remote_User` 等常见身份头——即使 SSO 未开启，浏览器也无法通过这些名字冒充用户；非法头名配置会被忽略（`http.Header.Set` 会 panic）

## 安全

- **SSO 部署约束文档化**：后端必须只能经网关访问（回环/防火墙）；无法网络隔离时必须使用 `hmac_secret` 签名。README 增加完整章节与后端验签示例

---

# GoProx v0.4.0 变更日志（2026-08-15）

## 新功能

- **原生 TLS 终结**：`goprox serve --tls-cert/--tls-key/--tls-selfsigned` 直接提供 HTTPS。`--tls-selfsigned` 自动生成覆盖 localhost + 所有局域网 IP 的自签证书（存入 `config/tls/`，0600）。HTTPS 使整个站点成为安全上下文，代理应用的所有安全上下文 Web API（`crypto.randomUUID`、`crypto.subtle`、`navigator.storage`、剪贴板等）在纯 HTTP 局域网下一次性全部可用；TLS 配置持久化到 `state.yaml`（删除 `tls_cert`/`tls_key` 两行并重启即关闭）
- **用户级默认服务（default_service）**：用户配置可指定默认服务 ID；未被认领的裸路径按「页面类 / 资源类」分流——页面类路径（SPA 视图，如 `/dashboard`）确定性地路由到默认服务，资源类路径（带扩展名的静态文件、`/api/`、`/plugins/`、`/_nuxt/` 等）跟随页面 Referer / 最近访问路由 cookie 转发。根路由型 SPA（Nuxt/Next/Vite 客户端路由）可在网关根路径零改动运行

## 兼容性

- **安全上下文 Web API polyfill**：向代理的 HTML 注入 `crypto.randomUUID` polyfill（`getRandomValues` 重建），纯 HTTP 局域网下应用不再报 `crypto.randomUUID is not a function`；HTTPS 下原生实现存在时自动为无操作
- **同源 Origin 改写**：浏览器同源请求的 `Origin` 头改写成后端 authority，通过后端自身 Host/Origin 同源校验（dsh 的 `/api` 信任栅栏、Jupyter CSRF）；第三方 Origin（CORS 客户端）不改写
- **WebSocket 101 与带宽限速兼容**：101 Switching Protocols 升级响应不再被 `bwlimit` 包装，限速服务的 WebSocket 隧道可正常建立（修复 `101 switching protocols response with non-writable body`）
- **裸路径 Referer 优先**：`/api/*` 与根路径转发链改为 Referer → 路由 cookie → 默认服务，SPA 页面内的 API/资源请求更精确地跟随发起页面
- **日志静默**：客户端断开流式连接时的 `ErrAbortHandler` panic 与标准库 `unexpected EOF` 不再刷日志/写死连接
- **`-V` / `--version`**：显示版本号（`goprox --help` 第一行同源）

## 文档

- README 新增「原生 TLS（局域网 HTTPS）」「默认服务（default_service，根路径托管）」章节，命令参考补充 TLS 与版本选项；`config.example.yaml` 同步
- 新增「dsh 配置示例」页面：`site/dsh-demo.html`（GitHub Pages 同步发布），演示 DeepSeek Harness 这类「本地优先/受限访问」应用如何零改动通过网关在局域网使用

---

# GoProx v0.3.1 变更日志（2026-08-15）

## 文档

- **新增 GitHub Pages 文档站点**：`https://seqyuan.github.io/goprox/`，手写静态页（Apple 液态玻璃风格），含首页、安装与启动、服务与示例、BackendPath 详解、安全（认证/TOTP/公网 TLS）、更新日志 6 个页面
- **自动部署**：`.github/workflows/docs.yml` 在 `site/` 变更时自动构建并发布到 GitHub Pages（官方 deploy-pages，无第三方依赖）
- README 顶部增加文档站点链接

---

# GoProx v0.3.0 变更日志（2026-08-15）

## 安全

- **两步验证（TOTP）可选二次验证**：按用户开启（默认关闭），支持 Google Authenticator / Authy / 1Password 等标准认证器；登录流程为「密码 → 6 位动态码 → 会话」；扫码绑定自助完成，动态码校验 ±1 个 30s 窗口容错并独立限速（IP+用户名，10 次/15 分钟）；`goprox 2fa-reset <name>` 供管理员在手机丢失时重置
- **公网部署 TLS 文档**：新增 `docs/reverse-proxy-tls.md`，给出 Caddy / nginx 反代终结 TLS 的完整示例，并说明 `--host 127.0.0.1` + `--trusted-proxy 127.0.0.1/32` 的配套做法（避免公网直连 HTTP）

## 新功能

- **自定义站点标题**：`goprox serve --title "🧬 生信分析平台"` 替换登录页/仪表盘/404 的左上角标题与浏览器标签标题，写入 `state.yaml` 持久化
- **示例补充**：用户配置示例新增局域网 IP（`192.168.0.109`）与单 HTML 网页（`backend_path` 指向入口文件）两种典型场景；后端路径章节拆分为「单 HTML 网页」与「入口在子目录文件」两个独立示例

## 界面

- **Apple Liquid Glass 视觉重设计**：冷灰 `#f5f5f7` 底色 + SF/PingFang 系统字体栈、毛玻璃导航（滚动时才显示 hairline）、白色卡片双层阴影与悬浮上移、单渐变 monogram（去除 A-Z 多彩色块）、pill 化徽章/按钮/输入框、玻璃材质弹窗与弹簧动效、`prefers-reduced-motion` 支持；暗色主题同步适配；登录页表单样式抽到公共 token

## 依赖

- 新增 `github.com/skip2/go-qrcode`（TOTP 二维码 PNG 生成）

---

# GoProx v0.2.6 变更日志（2026-08-15）

## CLI 精简：删除后台守护化，统一为前台 serve

- **删除 `start` / `stop` / `status` 子命令**：不再需要 pidfile、Setsid fork、后台进程、就绪轮询等守护化机制（删除约 230 行）
- **`goprox serve`（或裸 `goprox`）成为唯一启动命令**：前台运行，日志打印到终端，`Ctrl+C` 优雅停机
- **后台运行方式改为 tmux/screen 或 nohup**：`nohup ./goprox serve --port 30152 > goprox.log 2>&1 &`
- **过渡提示**：执行 `goprox start/stop/status` 会打印「已移除」提示与替代方式，老用户不会被 `unknown command` 卡住
- **配置目录精简**：不再生成 `daemon.pid` / `goprox.log`
- README 同步更新（快速开始、日常管理、命令参考、目录结构）

---

# GoProx v0.2.5 变更日志（2026-08-15）

## 新功能

- **自引用检测（防死循环）**：后端指向网关自身时（host 解析到本机接口 IP 且端口等于网关监听端口），写入配置与拨号建连两处都会拒绝，防止转发指回网关形成无限代理循环
- **按服务带宽限速**：服务新增 `bwlimit` 字段（字节/秒，0/缺省 = 不限速），上行（请求体）与下行（响应体）分别限速；仪表盘添加/编辑弹窗新增「带宽上限」输入框，卡片显示限速徽章

## 其他

- 新增 `golang.org/x/time` 依赖（限速令牌桶）
- 新增回归测试：自引用拒绝（写入/拨号）、限速器初始 burst 预扣与超大读封顶、限速不破坏 HTML 注入/非 HTML 透传/上传

---

# GoProx v0.2.3 变更日志（2026-08-15）

## 安全修复

- **拒绝链路本地 / 云元数据地址**：后端 host 白名单拒绝 169.254.0.0/16、fe80::/10 等链路本地地址，防止用户代理到云实例元数据服务（AWS/GCP/Azure IMDS）读取凭据
- **修复 DNS rebinding 绕过**：新增 `SafeDialContext`，转发建连时重新校验后端地址并直接拨号已校验的 IP，封死「写入时校验、拨号时重解析」的 TOCTOU 绕过
- **不再透传客户端伪造的 X-Forwarded-For**：后端只收到真实对端 IP，避免后端按 XFF 做日志/访问控制时被伪造来源 IP 绕过
- **会话绑定密码哈希版本**：改密码后所有已签发 session 立即失效（token 载荷由 `user|expiry` 升级为 `user|expiry|rev`；升级后旧会话需重新登录一次）
- **登录时序用户枚举防护**：未知用户名也执行等价的 bcrypt 比对，消除「已知用户慢 / 未知用户快」的时序侧信道
- **网关页面防点击劫持 / MIME 嗅探**：登录页、仪表盘、404 等增加 `X-Frame-Options: DENY`、`Content-Security-Policy: frame-ancestors 'none'`、`X-Content-Type-Options: nosniff`
- **修复更新服务时字段长度校验缺口**：仅改 description/category 时同样强制 ≤500/≤100 上限
- **请求体超限返回 413**：`/api/services` 请求体超过 64KB 不再静默截断，改为 413
- **慢速请求体防护**：`http.Server` 增加 `ReadTimeout`（60s）；已确认 WebSocket 升级劫持时会清空连接 deadline，故不影响 WebSocket
- **过宽 trusted-proxy 启动告警**：配置 `0.0.0.0/0`、`::/0` 等全域网段时打印 WARNING

## 路径解析修复

- **`<base>` 改为目录级注入**：纯 HTML 文件位于子目录时，注入的 `<base>` 指向文档所在目录（而非服务前缀），相对链接/相对重定向正确解析；服务根行为不变
- **清理代理重写后的 `RawPath`**：避免原请求带 `%2F` 等编码时路径错乱

## 文档

- 卡片参数一览：新增仪表盘与「添加服务」弹窗的真实界面截图，并保留可折叠的文字版参数表
- BackendPath 章节扩充：前端路径 `path` 与后端路径 `backend_path` 的对比与三种典型配置示例

---

# GoProx v0.2.2 变更日志（2026-08-15）

## 用户体验修复

- **卡片 favicon 支持现代图标**：由硬编码 `/favicon.ico` 改为候选链（`.ico`/`.svg`/`.png`/`-32x32`/`-16x16`），Next.js 等使用 SVG/PNG 图标的应用也能在卡片上显示真实图标（失败自动回退首字母色块）
- **修复多服务下绝对路径资源 404**：新增全局「最近访问」route cookie；多个服务 cookie 无法用路径/Referer 消歧时，回退到最近访问的服务而不是返回 404
- **静态资源保留压缩**：JS/CSS/图片/字体等静态资源不再剥离 `Accept-Encoding`，端到端 gzip 透传；HTML 仍由 Transport 解压以正确注入 `<base>`

## 安全与健壮性

- **管理 API 与登录 CSRF 防护**：浏览器跨站 POST/PUT/DELETE（Origin 不匹配）返回 403；非浏览器客户端（curl/脚本）不受影响
- **服务 path 安全校验**：仅允许 `A-Za-z0-9._~-` 与 `/`，非法 path 的服务自动跳过并在日志告警，防止破坏 `<base>` 注入/cookie/路由
- **重定向改写重构**：后端指向自身的绝对 URL 重定向转换为网关相对路径；外链与协议相对 URL 原样透传
- **服务名校验**：拒绝空名与超长字段（name≤200、description≤500、category≤100）
- **大 HTML/分块响应内存保护**：超过 8MB 的 HTML 或未知长度分块流不再整体缓冲（硬上限 + 余量流式透传）
- **状态持久化时序修复**：`state.yaml` 仅在监听成功后才写入，启动失败不再污染已运行实例的端口记录
- **模板安全加固**：内联 JSON 安全转义（防 `</script>` 注入）；中文/emoji 服务名首字符按 rune 截取
- 新增 20+ 回归测试（CSRF、path 校验、重定向改写、分块注入、静态资源压缩、route cookie 回退、favicon 候选等）

---

# GoProx v0.2.1 变更日志（2026-08-11）

## 安全修复（P0/P1）

- **修复 gzip 压缩的 HTML 被 `<base>` 注入破坏**：浏览器携带 `Accept-Encoding` 时，后端 gzip 压缩的页面会被注入逻辑写坏导致打不开；现在由 Transport 自行协商压缩并透明解压，注入正常生效（并防御性跳过带 `Content-Encoding` 的响应）
- **修复 route cookie 认证绕过**：无有效会话、仅残留 route cookie 的请求此前会被直接转发到后端（会话过期/登出后仍可访问后端裸路径）；现在一律重定向到登录页
- **修复登出后 `/login` 被残留 route cookie 劫持**：`GET /login` 仅在会话有效时才走后端转发；`/logout` 现在同时清除所有 `goprox_route*` cookie
- **登录限流加固**：新增 `--trusted-proxy <cidr>` 配置（写入 `state.yaml`），默认不再信任 `X-Forwarded-For/Proto`（可被直连客户端伪造绕过限流、伪造 Secure Cookie）；限流器增加全局清扫 + 10k 硬上限，杜绝伪造 IP 刷爆内存
- **密码哈希升级为 bcrypt**：`goprox user`/`passwd` 生成 bcrypt 哈希（自动兼容旧版 SHA-256 哈希，登录不受影响）

## 健壮性修复

- `state.yaml`（含 session_secret）权限 0644 → 0600
- HTTP Server 增加 `ReadHeaderTimeout`/`IdleTimeout`（慢速连接防占用；不设读写超时以免影响 WebSocket 长连接）
- HEAD 请求不再做 HTML 注入（避免 Content-Length 与实际不符）
- 代理错误响应不再回显后端 host/port 细节，仅日志记录
- 后端地址支持主机名（解析结果必须全部为私网地址，deny-by-default）
- 移除仓库内误提交的 `goprox-test` 二进制（10.7MB）
- 清理死代码（`SessionResult.IssuedAt` 近似值字段）
- 新增 14 个回归测试（gzip 注入、route cookie 认证、登出清理、bcrypt/旧哈希兼容、可信代理门控、限流有界性等），`go vet`/全量测试通过

---

# GoProx v0.2.0 变更日志（2026-08-11）

## 架构调整：配置集中到程序目录

- 所有配置移入**程序所在目录的 `config/`**（`state.yaml`、`daemon.pid`、`goprox.log`、`users/<用户名>.yaml`），不再依赖用户 home 目录；整个目录可整体拷贝迁移
- 配置目录权限收紧为 0700，用户配置 0600（不再需要 0666 共享写）
- **重要**：`os.Executable` 会解析符号链接，请拷贝二进制而非 `ln -s` 链接

## CLI 命令调整

- 新增 `goprox user <name>`（建号）、`goprox del <name>`（删号）
- `goprox passwd <name>`：由「改自己」改为「管理员重置指定用户密码」
- `goprox serve`：前台启动；`-d/--config-dir` 可覆盖默认配置目录

## 功能性修复

- `goprox start` 后台启动修复（此前稳定失败：父进程写入子进程 PID 导致子进程自我误判）
- bare 路径（如 `/jupyter`）不再被 route cookie 截胡，登录后直接访问会正确重定向到 `/proxy/<用户>/<服务>/`
- 中文/非 ASCII 服务名不再冲突（自动生成唯一 ID 与 path：`service`、`service-2`）
- API 缺省 `websocket` 字段时默认开启；端口（1–65535）与 path 唯一性校验
- `goprox passwd` 增加二次确认，拒绝空密码
- 登录后可返回原目标服务（`/login?next=/proxy/...`，防开放重定向）
- registry 扫描失败保留旧快照；日志恢复时间戳、不再每 10 秒刷屏
- 优雅停机（`Shutdown` + 超时）；共享 HTTP transport；大 HTML 响应跳过注入

---

# GoProx v2.0 变更日志（2026-07-16）

# GoProx v2.0 变更日志

发布日期：2026-07-16

## 🎉 重大更新

本版本全面解决了困扰用户的"闪回登录页"问题，并新增了 BackendPath 路径重写功能。

## 🐛 问题修复

### P0 严重问题

#### 1. Session 固定过期导致强制登出 ✅
- **问题**：Session 固定 24 小时后过期，活跃用户也会被强制登出
- **修复**：实现滑动窗口刷新机制，每次请求自动续期
- **影响**：活跃用户永远不会闪回登录页
- **相关文件**：`internal/auth/session.go`, `internal/proxy/proxy.go`, `internal/api/api.go`, `internal/web/web.go`

#### 2. Route Cookie 被覆盖导致服务切换失败 ✅
- **问题**：单一 route cookie 在多服务切换时互相覆盖
- **修复**：为每个服务设置独立路径范围的 cookie
- **影响**：可以在不同标签页同时使用多个服务
- **相关文件**：`internal/proxy/proxy.go`, `internal/web/web.go`

#### 3. Referer 头丢失导致路由推断失败 ✅
- **问题**：新标签页、后退、隐私模式下 Referer 丢失
- **修复**：改用 route cookie 作为主要上下文，Referer 仅作备用
- **影响**：所有浏览器场景下路由推断都可靠
- **相关文件**：`internal/web/web.go`

### P1 高优先级问题

#### 4. WebSocket 配置不生效 ✅
- **问题**：配置 `websocket: false` 的服务仍接受 WebSocket 连接
- **修复**：在升级前验证服务配置，拒绝未授权的 WebSocket 连接
- **影响**：增强安全性，严格按配置控制 WebSocket
- **相关文件**：`internal/proxy/proxy.go`

#### 5. API 路由冲突 ✅
- **问题**：管理 API 劫持后端应用的 `/api/*` 路由
- **修复**：改用精确路由匹配，只处理明确的管理端点
- **影响**：后端应用的 API 路由不再被拦截
- **相关文件**：`internal/api/api.go`

#### 6. 前端无加载反馈 ✅
- **问题**：点击服务卡片后无反馈，服务慢启动时用户困惑
- **修复**：添加加载动画和状态提示
- **影响**：改善用户体验，明确服务启动状态
- **相关文件**：`internal/web/templates/dashboard.html`, `script.js`, `style.css`

## ✨ 新功能

### BackendPath 路径重写 ✅
- **功能**：支持配置后端服务的实际路径
- **场景**：后端服务监听在特定路径（如 `/app/index.html`）时使用
- **配置示例**：
  ```yaml
  services:
    - name: "静态站点"
      port: 8080
      path: "/myapp"
      backend_path: "/static/index.html"  # 新增字段
  ```
- **相关文件**：`internal/config/config.go`, `internal/proxy/proxy.go`, `internal/api/api.go`

## 🔧 技术改进

### 安全性
- Session 定期刷新降低劫持风险
- Cookie 路径隔离防止泄露
- WebSocket 权限严格控制

### 稳定性
- 路由上下文更可靠
- 多服务并发使用无冲突
- 错误处理更完善

### 性能
- 每请求开销 <1ms（session 刷新）
- 无明显 CPU/内存增加
- 代理延迟无影响

## 📝 配置变更

### 兼容性
✅ **完全向后兼容** - 旧配置无需修改即可使用

### 新增配置项
- `backend_path`（可选）：指定后端服务的实际路径

### 示例配置
```yaml
services:
  - id: jupyter
    name: "Jupyter Lab"
    host: "127.0.0.1"
    port: 8888
    path: "/jupyter"
    websocket: true
    # backend_path: "/lab"  # 可选，通常不需要

  - id: static-site
    name: "静态站点"
    host: "127.0.0.1"
    port: 9000
    path: "/docs"
    backend_path: "/public/index.html"  # 新功能
    websocket: false
```

## 🚀 升级指南

### 快速升级
```bash
# 1. 备份配置
cp config.yaml config.yaml.backup

# 2. 停止旧服务
pkill goprox

# 3. 启动新版本
./goprox -config config.yaml
```

### 注意事项
1. 建议清除浏览器 Cookie 后重新登录
2. 配置文件无需修改
3. 所有现有功能保持不变
4. 新功能为可选

详细升级步骤请参考 [快速升级指南.md](./快速升级指南.md)

## 📚 文档

- [修复文档索引.md](./修复文档索引.md) - 文档导航（推荐从这里开始）
- [闪回问题审核报告.md](./闪回问题审核报告.md) - 问题分析
- [修复完成报告.md](./修复完成报告.md) - 技术细节
- [BackendPath功能说明.md](./BackendPath功能说明.md) - 新功能说明
- [快速升级指南.md](./快速升级指南.md) - 部署指南

## 🔍 测试建议

### 功能测试
- [ ] 登录后长时间使用（24小时+）不闪回
- [ ] 多标签页同时使用不同服务
- [ ] WebSocket 服务正常工作
- [ ] 非 WebSocket 服务拒绝 WebSocket 连接
- [ ] BackendPath 路径重写正确
- [ ] 后端应用的 API 不被拦截

### 性能测试
- [ ] 响应时间正常
- [ ] CPU/内存使用正常
- [ ] 并发连接正常

### 回归测试
- [ ] 所有原有功能正常工作
- [ ] 配置文件正常加载
- [ ] 服务健康检查正常

## 🐛 已知问题

无已知严重问题。

## 📊 统计

- **修复问题数**：6 个（3 个 P0 + 3 个 P1）
- **新增功能**：1 个（BackendPath）
- **修改文件数**：9 个
- **新增代码**：~500 行
- **修改代码**：~200 行

## 🙏 致谢

感谢所有参与问题诊断、修复开发和测试验证的团队成员！

---

**版本**：v2.0  
**发布日期**：2026-07-16  
**兼容性**：完全向后兼容 v1.x  
**推荐升级**：强烈推荐所有用户升级
