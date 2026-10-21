# 基于 Host 的虚拟主机服务（大改）方案

> 状态：Phase 1 已实现（未发布）；Phase 2/3 未实现。
> 日期：2026-10-21
> 背景：`root_absolute` 解决了“从已加载页面发起的站内跳转”，但无法覆盖收藏夹直访、
> `no-referrer`、应用必须拥有根路径 `/` 等情况。彻底方案是让每个服务拥有独立 Host，
> 在根路径直接代理该服务。

> 实现说明：Phase 1 已按本文落地——显式 `hostnames`、父域会话 Cookie、外部 TLS 反代、
> 默认关闭、保留路径模式。`redirectBareService` 未修改；主 Host 裸路径行为不变。

## 1. 目标与非目标

### 目标

- 允许一个服务绑定一个或多个独立主机名，例如：

  ```text
  https://gw.example.com/          → GoProx 仪表盘
  https://hugo.gw.example.com/     → Hugo 服务，路径原样转发
  https://jupyter.gw.example.com/  → Jupyter，路径原样转发
  ```

- 服务在独立 Host 下拥有根路径：
  - `/docs/` → 后端 `/docs/`
  - `/static/...` → 后端 `/static/...`
  - 不再需要 `root_absolute`、`default_service` 或 `<base>` 兼容。
- 保留现有路径模式：
  - `/proxy/<user>/<service>/...`
  - 服务 `path` / `default_service`
  - 现有用户配置不迁移也能继续工作。
- 认证仍然由 GoProx 统一负责，未登录访问服务 Host 时跳转主网关登录。
- Host 路由默认关闭，必须显式配置 `hostnames` 才启用。

### 非目标

- 不做通配子域名自动分配（如 `<service>.<user>.gw.example.com`）作为第一阶段；
  第一阶段使用显式 `hostnames`，避免与现有用户名/服务 ID 规则耦合。
- 不替代现有路径代理；两种模式并存。
- 不在第一阶段实现多证书 SNI 管理；先支持一个通配证书或外部 TLS 反代。
- 不做跨集群、多网关共享 Host 索引。
- 不隔离后端应用自己的 Cookie；只处理 GoProx 自身 Cookie 与代理边界。

## 2. 现状与限制

当前 `Server.Handler()` 完全按路径构建 mux：

```go
mux.HandleFunc("/api/services", ...)
mux.HandleFunc("/login", ...)
mux.HandleFunc("/proxy/", ...)
mux.HandleFunc("/", ...)
```

会话 Cookie `goprox_session` 是 host-only（无 `Domain`），所以主网关登录后，
浏览器不会把会话发给 `hugo.gw.example.com`。

`proxy.NewReverseProxy` 当前按路径前缀模式工作：

- `fc.Prefix = /proxy/<user>/<service>`
- `fc.Base = prefix + "/"`
- `rewriteLocation` 会把后端绝对重定向加上 `fc.Prefix`
- `X-Forwarded-Prefix = fc.Prefix`
- 后端 Cookie 在 canonical 路径下会被重写 Path

这些行为与“服务拥有独立 Host、根路径”不兼容，需要新增 vhost/as-is 模式。

## 3. 总体架构

### 3.1 Host 路由

请求进入后，先按 `r.Host` 查虚拟主机索引：

```text
Host = hugo.gw.example.com
  → 命中 (username=alice, service=hugo)
  → 认证
  → vhost 模式原样代理到后端

Host = gw.example.com 或未知 Host
  → 继续现有路径 mux（仪表盘 / /proxy / /api）
```

未知 Host 不直接 404，而是回落到现有路径 mux，保证：

- 用户用 IP、旧域名、反代 Host 访问时行为不变；
- 只有显式配置的 `hostnames` 才进入 vhost 模式。

> 注意：服务 Host 上**所有路径**（包括 `/login`、`/logout`、`/api/services`）都归应用；
> GoProx 仪表盘、登录、服务管理入口只在主 Host 提供。未登录访问服务 Host 时由网关
> 跳转主 Host 登录，登录后再回到服务 Host。
>
> vhost 请求在进入 mux 之前就被处理，因此**不会经过** `redirectBareService`、
> `handleDefaultServicePage`、`handleRootAbsoluteService` 等裸路径逻辑。

### 3.2 认证与跳转

服务 Host 上：

1. 读取 `goprox_session`；
2. 会话有效且用户 == 服务所属用户 → 代理；
3. 会话有效但用户不匹配 → 404（隐藏该 Host 是否存在）；
4. 无会话/过期 → 302 到主网关：

   ```text
   https://gw.example.com/login?next=https%3A%2F%2Fhugo.gw.example.com%2Fdocs%2F
   ```

5. 登录成功（含 2FA）后，校验 `next`：
   - host 必须是该用户已配置的 `hostnames` 之一；
   - scheme 只允许 http/https；
   - 校验通过后 302 回服务 Host。

这样浏览器在主网关登录后拿到带 `Domain` 的会话 Cookie，再访问服务 Host 时自动带上。

### 3.3 两种会话方案

#### 方案 A：父域 Cookie（第一阶段推荐）

登录时设置：

```text
goprox_session=...; Domain=.gw.example.com; Path=/; HttpOnly; SameSite=Lax; Secure
```

- 优点：实现简单，所有子域共享登录态，跳转自然。
- 缺点：
  - 需要配置 `cookie_domain`；
  - 所有子域都会收到会话 Cookie（后端请求会被 GoProx 剥离，但仍需防 Cookie tossing）；
  - 不能使用 `__Host-` 前缀（要求 host-only）。
- 适用：单实例、可信实验环境、统一父域。

#### 方案 B：每 Host 一次性 Token 交换（后续可选）

未登录访问服务 Host 时：

```text
302 主网关 /login?next=...
登录成功后 302 https://hugo.gw.example.com/_goprox/auth?code=<short-lived-signed-token>
服务 Host 的网关端点校验 code，设置 host-only session cookie，再 302 回原路径
```

- 优点：不需要父域 Cookie，隔离更强。
- 缺点：
  - 需要额外端点、短时 token、重放保护；
  - 登录流程与 2FA 跳转更复杂；
  - URL 中短暂出现 token，必须 HTTPS + 短 TTL。
- 适用：对子域隔离要求高的部署。

第一阶段只做方案 A；方案 B 作为后续安全增强。

## 4. 配置设计

### 4.1 网关级配置

在 `config/state.yaml` 增加：

```yaml
server:
  host: 0.0.0.0
  port: 30152
  # 主网关对外地址，用于登录跳转与卡片链接
  public_host: "gw.example.com"
  # 可选：对外 scheme，默认根据 TLS/反代判断；用于生成绝对 URL
  public_scheme: "https"
  # 会话 Cookie 的父域；启用 vhost 时必填，例如 ".gw.example.com"
  cookie_domain: ".gw.example.com"
```

建议新增结构：

```go
type ServerState struct {
    ...
    PublicHost   string `yaml:"public_host,omitempty"`
    PublicScheme string `yaml:"public_scheme,omitempty"`
    CookieDomain string `yaml:"cookie_domain,omitempty"`
}
```

- `public_host` 为空时，回退到请求的 `r.Host`（兼容单机/反代）。
- 启用任何 `hostnames` 但 `cookie_domain` 为空时，启动报错或明确警告：
  - 推荐报错，避免“登录后又跳回登录页”的隐蔽故障。
- `cookie_domain` 必须是 `.` 开头的父域或精确域；校验不能是公共后缀（如 `.com`）。

### 4.2 服务级配置

`ServiceConfig` 增加：

```go
Hostnames []string `yaml:"hostnames,omitempty" json:"hostnames,omitempty"`
```

示例：

```yaml
services:
  - id: hugo
    name: Hugo 预览
    host: 127.0.0.1
    port: 1313
    path: /hugo              # 仍然保留，用于 /proxy 路径访问
    hostnames:
      - hugo.gw.example.com
    websocket: true
```

规则：

- 小写、去尾点；不允许 scheme、path、port、通配符；
- 全局唯一：不同用户/服务不能声明同一个 Host；
- 不能等于 `server.public_host`；
- 只在 vhost 模式生效；`path` 仍然用于现有 `/proxy` 路径访问；
- `backend_path` 在 vhost 模式下仍可选应用（见 §6）；
- `root_absolute` 对 vhost 服务不再必要，但保留兼容。

### 4.3 配置持久化

- 必须加入 `serializeServices`，否则卡片编辑/排序会丢字段。
- `UpdateService` 默认保留未修改字段；如果后续 UI 支持编辑 `hostnames`，再扩展
  `ServiceUpdate` / `addServiceBody` / `updateBody`。
- 第一阶段建议 YAML-only，避免 UI 表单与全局唯一性校验的复杂度。

### 4.4 配置校验

在 `LoadUserConfig` 做单用户内校验：

- Host 语法；
- 同一用户内不重复。

跨用户唯一性只能在 `UserRegistry.Reload()` 时检查：

- 构建 Host → (user, service) 索引；
- 发现重复时：
  - 启动阶段：返回错误，拒绝启动；
  - 周期 reload：记录 error，保留上一个有效索引或禁用冲突 Host；
  - 推荐：启动 fail-fast，reload 时保留旧索引并打印告警。

## 5. 请求路由流程

### 5.1 Handler 入口

在 `Server.Handler()` 的最外层增加 Host 路由：

```go
func (s *Server) Handler() http.Handler {
    mux := http.NewServeMux()
    // ... existing routes ...

    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        defer recover...
        if host, ok := normalizeVHost(r.Host); ok {
            if s.handleVirtualHost(w, r, host) {
                return
            }
        }
        mux.ServeHTTP(w, r)
    })
}
```

`handleVirtualHost` 只对索引中存在的 Host 返回 true；未知 Host 回落现有 mux。

### 5.2 vhost 认证

```go
func (s *Server) handleVirtualHost(w, r, host) bool {
    target := s.registry.FindByHost(host)
    if target == nil {
        return false
    }

    session := s.sessionFromCookies(r.Header.Get("Cookie"))
    if !session.Valid || session.UserID == "" {
        redirectToMainLogin(w, r, host)
        return true
    }
    if session.UserID != target.Username {
        sendHTML(w, 404, web.NotFoundPage(...))
        return true
    }

    // refresh session if needed, with Domain cookie
    ...
    s.proxyVHost(w, r, target)
    return true
}
```

### 5.3 登录 `next` 安全校验

当前 `validLoginNext` 只允许 `/proxy/...` 相对路径。需要扩展为：

```go
func (s *Server) validLoginNext(next, username string) bool {
    // 1. existing /proxy/... relative path
    // 2. absolute http(s) URL whose host belongs to username's services
}
```

关键点：

- 登录页 GET 不做用户相关校验，只把 `next` 放入隐藏字段；
- 密码校验成功后（以及 2FA 成功后）才用 `username` 校验绝对 URL；
- 绝对 URL 必须：
  - scheme 是 http/https；
  - host 在 `hostnames` 索引中；
  - 该 Host 属于刚登录的 `username`；
  - 不允许 userinfo、fragment、// 开头、非配置 Host。
- 防止开放重定向。

2FA 流程：

- 待验证 token 仍使用主网关 host-only cookie；
- `next` 原样通过 `/login/2fa` 传递；
- 2FA 成功后再做绝对 URL 校验并跳转。

### 5.4 与 `redirectBareService` 的关系

**Phase 1 不修改 `redirectBareService`**，但需要明确两种入口的行为：

| 请求 | 行为 |
| --- | --- |
| 主 Host `/hugo/...`，服务配置了 `hostnames` | 保持现状：`redirectBareService` → `/proxy/alice/hugo/...` |
| 服务 Host `https://hugo.gw.example.com/hugo/...` | vhost 路由直接原样转发，不经过 `redirectBareService` |
| 服务 Host `https://hugo.gw.example.com/docs/` | vhost 路由直接原样转发，不经过 `redirectBareService` |
| 主 Host `/proxy/alice/hugo/...` | 保持现状，canonical 路径代理 |

原因：

- `redirectBareService` 是主 Host 路径模式的一部分，vhost 请求在 mux 之前已经分流；
- 服务 `path` 与 `hostnames` 可以并存，主 Host 的 `/hugo/...` 仍然可用；
- 不在 Phase 1 改变现有用户的裸路径重定向行为。

需要单独决策（建议 Phase 2）：

- 配置了 `hostnames` 的服务，主 Host 的裸路径 `/hugo/...` 是否应该直接 302 到
  `https://hugo.gw.example.com/...`，而不是 `/proxy/...`？
- 如果要做，应在 `redirectBareService` 中检查服务的 `hostnames`，并选择一个 primary
  Host；同时保留配置开关，避免改变默认行为。

Phase 1 必须补的回归测试：

- 主 Host `/hugo/...` 仍然 302 到 `/proxy/alice/hugo/...`；
- 服务 Host `/hugo/...` 和 `/docs/` 都原样转发，不触发 302；
- 服务同时配置 `path` 与 `hostnames` 时，两种入口互不干扰。

## 6. Proxy vhost/as-is 模式

`ProxyForwardContext` 建议增加显式模式：

```go
type ForwardMode int

const (
    ForwardPrefix ForwardMode = iota // existing /proxy/<user>/<service>
    ForwardAsIs                      // bare path / default_service
    ForwardVHost                     // dedicated host, root ownership
)
```

或者用布尔字段 `VHost bool`，但显式枚举更利于后续扩展。

### 6.1 vhost 模式行为

| 字段/行为 | 路径模式 | vhost 模式 |
| --- | --- | --- |
| `Base` | `/proxy/<user>/<svc>/...` 计算 | `BaseForPath("", r.URL.Path)` |
| `X-Forwarded-Prefix` | `/proxy/<user>/<svc>` | 空 |
| `rewriteLocation` | 后端绝对路径加 `/proxy/...` 前缀 | 保持为后端路径（仅把绝对 URL 转成 path） |
| route cookie | 设置 | 不设置（Host 已标识服务） |
| 后端 Set-Cookie Path | canonical 前缀化 | 保持原 Path |
| 网关 Cookie 剥离 | 是 | 是 |
| 后端 Cookie 与网关 Cookie 重名 | 现有行为 | 直接丢弃该 Set-Cookie |
| `backend_path` | 应用 | 可选应用（默认建议为空） |
| WebSocket / SSO / 限速 | 支持 | 支持 |

### 6.2 Location 重写

`rewriteLocation` 需要模式感知：

- `ForwardVHost`：
  - 后端返回 `Location: /docs` → 保持 `/docs`；
  - 后端返回 `Location: http://127.0.0.1:1313/docs` → 转成 `/docs`；
  - 外部 URL 原样透传；
- `ForwardPrefix`：保持现状，加前缀；
- `ForwardAsIs`：当前最小实现仍加前缀（已知限制），后续可统一到 vhost 语义。

### 6.3 Cookie 处理

- vhost 模式下 `RewriteSetCookie(raw, "", secure)`，保留后端 Path。
- **新增防 Cookie tossing**：如果后端 `Set-Cookie` 的 name 等于 GoProx 自身 Cookie
  （session / 2fa / route / 可配置前缀），直接丢弃该 Cookie。
  - 否则恶意/异常后端可在服务 Host 上设置同名 host-only Cookie，遮蔽父域会话 Cookie。
- `__Host-` / `__Secure-` 规则继续沿用现有实现。

## 7. Cookie 与会话

### 7.1 会话 Cookie 域

`auth.SetSessionCookie` / `ClearSessionCookie` 需要支持 Domain：

```go
func SetSessionCookie(secret string, ttlSec int, userID, rev string, secure bool, domain string) string
```

或者增加 `CookieOptions{Domain, Secure}`，减少参数继续膨胀。

- 主网关登录：`Domain=.gw.example.com`；
- 主网关 logout：必须带同样的 Domain 清除，否则父域 Cookie 清不掉；
- 2FA pending/setup：仍 host-only 主网关；
- route cookie：host-only，按服务 Host 自然隔离；
- 服务 Host 上不设置会话 Cookie（方案 A）。

### 7.2 与 Cookie 命名空间方案的关系

`docs/plans/2026-10-19-configurable-cookie-names.md` 的 `cookie_suffix` 方案与
vhost 不冲突：

- 多实例同父域时，仍需要不同 Cookie 后缀；
- vhost 模式下父域 Cookie 的名称必须与路径模式一致；
- 建议在 vhost 第一阶段只支持单实例，暂不强制实现 Cookie 后缀。

### 7.3 安全注意

- 父域 Cookie 会发送到所有子域；GoProx 必须在转发前剥离；
- 后端不得覆盖网关 Cookie 名（见 §6.3）；
- `HttpOnly`、`Secure`（HTTPS）、`SameSite=Lax` 必须保留；
- 使用 HTTPS；HTTP 下父域会话 Cookie 风险很高。

## 8. TLS 与 DNS

### 8.1 第一阶段：外部 TLS 反代（推荐）

```text
浏览器 → Caddy/nginx（*.gw.example.com 通配证书） → GoProx HTTP
```

- Caddy/nginx 负责 TLS、转发原始 Host、设置 `X-Forwarded-Proto`；
- GoProx 配置 `trusted_proxy`，只信任来自反代的 `X-Forwarded-*`；
- DNS：`*.gw.example.com` 指向反代；
- GoProx 不需要改 TLS 代码，只需要 Host 路由。

### 8.2 第二阶段：GoProx 原生通配 TLS

现有 `server.tls_cert` / `tls_key` 可以用一张 `*.gw.example.com` 通配证书；
Go 的 TLS 会对所有 SNI 返回同一张证书，覆盖一级子域。

限制：

- 只覆盖一个层级（`*.gw.example.com` 不含 `a.b.gw.example.com`）；
- 多父域/多证书需要 `tls.Config.GetCertificate` + SNI 映射，属于后续增强。

### 8.3 DNS

- 通配 DNS：`*.gw.example.com → 网关 IP`；
- 或为每个 `hostnames` 建 A/CNAME；
- 证书必须覆盖实际 Host；
- 内网可用 `.lan` / 自建 DNS，但浏览器对自签证书仍有警告。

## 9. Registry Host 索引

`UserRegistry` 增加：

```go
type HostTarget struct {
    Username string
    Service  *ServiceConfig
}

hosts map[string]HostTarget
```

- `Reload()` 构建 `newUsers` 后，同时构建 `newHosts`；
- 重复 Host：
  - 记录 error；
  - 启动时 `Reload` 可返回错误（需要调整签名或新增 `ReloadChecked`）；
  - 周期 reload 保留旧索引并打印告警，避免瞬时故障清空路由；
- `FindByHost(host)`：
  - `EnsureFresh()`；
  - 返回当前快照的 user/service；
  - 调用方只读，不修改指针。
- Host 规范化：
  - 小写；
  - 去掉端口（`r.Host` 可能含端口）；
  - 去掉尾点；
  - 拒绝空 Host、IP（第一阶段）或允许 IP 但明确无 TLS 通配。

## 10. Dashboard / API / UI

第一阶段：

- 卡片链接仍然使用 `/proxy/...`，保证旧行为；
- 如果服务配置了 `hostnames`，卡片可以优先使用
  `https://<primary-host>/`（第二阶段）；
- `hostnames` 先只支持 YAML；
- 后续在添加/编辑表单增加“独立域名”输入，并做全局唯一性提示。

## 11. 安全清单

- [ ] Host 路由只对显式配置的 Host 生效，未知 Host 回落路径 mux。
- [ ] Host 必须属于会话用户；跨用户 403。
- [ ] 登录 `next` 绝对 URL 必须匹配该用户 Host，防开放重定向。
- [ ] 父域 Cookie 只在 HTTPS 下启用 `Secure`；生产必须 HTTPS。
- [ ] 后端 `Set-Cookie` 不得覆盖 GoProx Cookie 名。
- [ ] 转发前剥离所有 GoProx Cookie。
- [ ] `trusted_proxy` 限制 `X-Forwarded-*` 信任范围。
- [ ] Host 头注入/伪造不能访问未授权服务。
- [ ] 重复 Host 配置 fail-fast 或告警。
- [ ] 服务删除/用户删除后 Host 索引及时失效。

## 12. 分阶段交付

### Phase 0：设计验证（0.5–1 天）

- 用 Caddy/nginx 配置 `*.gw.example.com` + 反代到现有 GoProx；
- 验证 DNS、通配证书、`X-Forwarded-Proto`、`trusted_proxy`；
- 确认浏览器 Cookie Domain 行为与登录跳转。

### Phase 1：核心 vhost 路由（3–5 天）

- 配置字段 `hostnames` / `public_host` / `cookie_domain`；
- Registry Host 索引与重复检查；
- Handler Host 路由；
- 父域会话 Cookie；
- vhost 代理模式（base / location / X-Forwarded-Prefix / cookie）；
- 登录 `next` 安全校验；
- 单元/集成测试 + 文档。

### Phase 2：原生 TLS 与 UI（2–4 天）

- 通配证书配置与文档；
- 多证书 SNI（可选）；
- 卡片优先使用 vhost；
- UI 编辑 `hostnames`（可选）。

### Phase 3：每 Host Token 交换（3–5 天，可选）

- 短时签名 code；
- `/_goprox/auth` 端点；
- host-only session cookie；
- 重放/过期/HTTPS 校验。

## 13. 实施任务清单（Phase 1）

### Task 1：配置字段与校验

**Files:**
- Modify: `internal/config/state.go`
- Modify: `internal/config/user.go`
- Test: `internal/config/*_test.go`

- `ServerState.PublicHost` / `PublicScheme` / `CookieDomain`
- `ServiceConfig.Hostnames`
- 加入 `serializeServices`
- Host 语法/单用户重复校验
- 测试：序列化保留、编辑保留、非法 Host 拒绝

### Task 2：Registry Host 索引

**Files:**
- Modify: `internal/config/registry.go`
- Test: `internal/config/registry_test.go`（或现有测试文件）

- `hosts` map + `FindByHost`
- Reload 重建索引
- 跨用户重复检测
- 测试：查找、重复、reload、删除用户

### Task 3：Host 路由与登录跳转

**Files:**
- Modify: `internal/server/server.go`
- Modify: `internal/web/templates/*`（如需登录提示）
- Test: `internal/server/*_test.go`

- 最外层 Host 路由
- 未登录 302 主网关登录
- 用户不匹配 404
- 登录 `next` 绝对 URL 校验
- 确认 vhost 路由在 mux 之前完成，`redirectBareService` 保持现状
- 测试：无 Cookie、错误用户、正确用户、未知 Host；主 Host 裸路径仍 302 到 `/proxy/...`；服务 Host 路径不触发 302

### Task 4：vhost 代理模式

**Files:**
- Modify: `internal/proxy/proxy.go`
- Modify: `internal/proxy/cookie.go`
- Test: `internal/proxy/*_test.go`

- `ForwardMode` / `VHost`
- base 计算
- `rewriteLocation` 模式感知
- `X-Forwarded-Prefix` 为空
- 不设置 route cookie
- 后端 Cookie 同名丢弃
- 测试：Location、base、Cookie、X-Forwarded-Prefix

### Task 5：父域会话 Cookie

**Files:**
- Modify: `internal/auth/auth.go`
- Modify: `internal/server/server.go`
- Test: `internal/auth/*_test.go`, `internal/server/*_test.go`

- `SetSessionCookie` / `ClearSessionCookie` 支持 Domain
- 登录/logout 使用配置 Domain
- 测试：Set-Cookie 含 Domain、logout 清除同 Domain
- 测试：2FA/route Cookie 仍 host-only

### Task 6：集成测试与部署文档

**Files:**
- Test: `internal/server/*_test.go`
- Modify: `README.md`
- Modify: `config.example.yaml`
- Modify: `docs/CHANGES.md`

- `httptest` + `req.Host` 模拟多个 Host；
- 可选 Playwright 使用 `*.localhost`；
- Caddy/nginx 通配 TLS 示例；
- DNS/证书/`trusted_proxy` 配置说明。

## 14. 工作量与风险

| 项目 | 评估 |
| --- | --- |
| Phase 1 代码量 | 约 800–1500 行（含测试） |
| Phase 1 工时 | 3–5 个工作日 |
| Phase 2 工时 | 2–4 个工作日 |
| Phase 3 工时 | 3–5 个工作日 |
| 最大风险 | 跨子域认证、父域 Cookie 安全、开放重定向、Cookie tossing |
| 运维依赖 | 通配 DNS、通配 TLS、反代/`trusted_proxy` |
| 兼容性 | 默认关闭；未配置 `hostnames` 的行为完全不变 |

## 15. 建议

1. **先做 Phase 0 的部署验证**：用 Caddy/nginx + 通配证书确认 DNS、TLS、
   `X-Forwarded-Proto`、Cookie Domain 在实际浏览器中的行为。
2. **Phase 1 只做“显式 hostnames + 父域 Cookie + 外部 TLS 反代”**。
   不建议一开始就做原生多证书 SNI 或每 Host token 交换。
3. **保留路径模式**，不要用 vhost 替换 `/proxy`；两张模式并存，降低迁移风险。
4. **不要把这个方案和当前 `root_absolute` 混在一起**：
   - `root_absolute` 是轻量兼容层；
   - vhost 是架构级功能，独立发布、独立回滚。
5. 如果目标只是 Hugo/少数根绝对路径应用，优先继续用：
   - 应用自身 `baseURL`；
   - `root_absolute`；
   - 或独立域名/端口 + 外部反代。
   只有在“多个服务都需要真正拥有独立 Origin”时，才值得投入 vhost。

## 16. 替代方案对比

| 方案 | 完整性 | 复杂度 | 适用 |
| --- | --- | --- | --- |
| 应用 baseURL | 完整 | 低 | 能改应用配置 |
| `root_absolute` | 站内跳转 | 低 | 不能改应用、单实例 |
| vhost（本方案） | 完整 Owner Origin | 高 | 多应用、长期平台化 |
| HTML/CSS URL 重写 | 不完整 | 很高 | 不推荐 |
| 外部反代 + SSO header | 完整（但绕过 GoProx 会话） | 中 | 不需要 GoProx 统一登录 |

## 17. 需要确认的问题

1. 是否已有可用的通配域名与通配证书，例如 `*.gw.example.com`？
2. 是否接受父域会话 Cookie（`.gw.example.com`），还是必须使用每 Host token 交换？
3. 第一阶段是否接受外部 Caddy/nginx 终止 TLS，还是必须由 GoProx 原生监听 443？
4. Host 命名采用显式 `hostnames`（推荐），还是希望自动生成
   `<service>.<user>.<domain>`？
5. 服务的 `path` 与 vhost 是否需要同时保留？本方案默认两者并存。
6. 配置了 `hostnames` 的服务，主 Host 的裸路径 `/hugo/...` 是继续跳
   `/proxy/...`，还是直接 302 到 `https://hugo.../...`？Phase 1 默认保持现状。

## 18. 结论

这是可行的，但属于 **架构级改动**，不是 `root_absolute` 的简单升级。建议按 Phase 0 → Phase 1 推进，先解决“显式 Host + 父域会话 + 外部 TLS 反代”，再考虑原生 TLS/SNI 和每 Host token 交换。默认关闭、保留路径模式，是控制风险的关键。
