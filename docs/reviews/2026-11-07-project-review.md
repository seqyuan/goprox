# GoProx 项目审查报告

| 项 | 内容 |
|---|---|
| 审查日期 | 2026-11-07 |
| 仓库 | `github.com/seqyuan/goprox` |
| 审查范围 | 架构、安全敏感路径、测试与 CI、可维护性、文档 |
| 方法 | 静态代码阅读 + 全量 `go test ./...` / `-cover`；未做公网渗透或生产流量复现 |
| 结论摘要 | **无 Critical 级别缺陷**；全量测试通过。产品定位清晰，出站与会话安全设计成熟。优先处理多租户路径权限与 PR CI，并拆分过大的路由/配置文件。 |

---

## 1. 执行摘要

GoProx 是面向实验室 / 登录节点的**多用户认证反向代理网关**：运维启动共享入口并创建账号，用户在网页上管理各自的 Jupyter / RStudio / 内网服务卡片。依赖面很小（`yaml.v3`、`x/crypto`、`x/time`、`go-qrcode`），配置与二进制同目录存放，文档与示例较完整。

整体判断：

- **安全边界**（私网出站、拨号再校验、Cookie/CSRF、自环拒绝）明显成熟于同类「自建反代」。
- **测试文化**良好：测试代码行数接近生产代码，核心包覆盖率高。
- 主要风险不在「明显漏洞」，而在 **多租户下的本机路径权限模型**、**缺少 PR 持续集成**，以及 **server / config / main 文件过大**带来的后续改动成本。

---

## 2. 审查时基线

### 2.1 测试结果

```text
go test ./...
ok  github.com/seqyuan/goprox
ok  github.com/seqyuan/goprox/internal/{api,auth,config,files,proxy,rate,server,web}
```

全部通过（审查日本地执行）。

### 2.2 语句覆盖率（`go test ./... -cover`）

| 包 | 覆盖率 | 生产代码约 LOC | 角色 |
|---|---|---|---|
| `internal/rate` | 88.3% | 214 | 登录/TOTP 失败限流、带宽 IO |
| `internal/proxy` | 83.2% | 1012 | 反向代理、Cookie 重写、SSO、auth_bootstrap |
| `internal/files` | 80.5% | 523 | 只读目录浏览 / ZIP（`os.Root`） |
| `internal/auth` | 80.3% | 753 | 会话、密码、TOTP、Cookie、可信代理 |
| `internal/web` | 77.3% | 372 | 登录 / 仪表盘 HTML |
| `internal/config` | 76.3% | 2571 | state/users、host allowlist、registry |
| `internal/api` | 69.9% | 525 | 服务 CRUD API + CSRF |
| `internal/server` | 59.9% | 1586 | HTTP 入口与全部路由模式 |
| `main`（含 CLI/TLS） | 22.7% | ~925 | serve、用户管理、TLS 启动 |

粗算：生产 Go 代码约 **8.5k** 行，测试约 **7.7k** 行。

### 2.3 架构一览

```text
客户端
  → main / tls（CLI、serve、原生 TLS）
    → internal/server（路由编排：登录/2FA/vhost/代理分发）
      ├─ internal/api + internal/web     管理面
      ├─ internal/auth + internal/rate   认证与限流
      ├─ internal/proxy                  出站反向代理 / SSO / bootstrap
      ├─ internal/files                  内置只读文件服务
      └─ internal/config                 state.yaml + users/*.yaml
```

请求路径除 `/proxy/<user>/<svc>/...` 外，还有 vhost、`Referer` / route-cookie / `default_service` / `root_absolute` 等裸路径兼容层，功能覆盖面宽，也是 `server.go` 体量大的主要原因。

---

## 3. 发现汇总

| 级别 | 数量 | 说明 |
|---|---|---|
| Critical | **0** | 未发现需立即停用或紧急热修的代码级缺陷 |
| Important | **3** | 建议在下一迭代处理 |
| Minor | **4** | 可排入中期 backlog |
| Strength | **3** | 应保留并在评审时作为设计基线 |

---

## 4. Important（建议优先处理）

### I-1. 多租户：登录用户可配置任意本机可读路径

**区域：** 权限模型 / `kind: files` / `auth_bootstrap`  
**证据：** `internal/config/user.go`（`ValidateFileRoot`）、`internal/files`、服务配置中的 `auth_bootstrap.token_file` / `token_log`

**问题：**

- `kind: files` 的 `root` 由**登录用户**在仪表盘或配置里填写绝对路径。
- `auth_bootstrap` 可指定本机上的 `token_file` / `token_log`。
- 校验保证「路径存在且对网关进程可读」，**不限制**「是否属于该用户」。

因此，凡是 **goprox 进程 UID 能读到的路径**（他人家目录、共享盘、含密钥的配置目录等），都可能被挂成文件浏览卡片，或用于读取令牌文件/日志。这是典型的 **confused deputy**：认证挡住的是外网匿名访问，挡不住**已登录合法用户**的横向读盘。

**影响：** 在「多人共用同一网关进程、进程权限较宽」的实验室部署中，信任边界弱于「每用户只能看自己的服务端口」的直觉。

**建议（任选或组合）：**

1. 管理员在 `state.yaml` 配置路径白名单（前缀列表），用户 `root` / bootstrap 路径必须落在白名单内。
2. 或仅允许 `files` / bootstrap 由管理员 CLI 写入，仪表盘禁止自填任意绝对路径。
3. 运维文档明确：生产环境应以最小权限用户运行 goprox，并配合文件系统 ACL / `ProtectHome=` 等 systemd 加固。

---

### I-2. PR / 日常 push 无持续测试门禁

**区域：** CI  
**证据：** `.github/workflows/release.yml`、`.github/workflows/docs.yml`

**问题：**

- `go test ./...` 目前挂在 **打 `v*` release tag** 的 release workflow 里。
- `docs.yml` 只负责 GitHub Pages。
- `main` 上的日常提交 / PR **没有**自动跑测试或 `go vet`。

回归依赖贡献者本地 `make test`，容易漏检。

**建议：** 新增 workflow，在 `pull_request` 与 `push` 到 `main` 时执行：

```text
go test ./...
go vet ./...
```

（可选）`gofmt -l` 检查。与现有 release 矩阵解耦，保持轻量、快速失败。

---

### I-3. 路由与配置集中在超大文件，可维护性风险高

**区域：** 可维护性  
**证据：**

| 文件 | 约行数 | 内容 |
|---|---|---|
| `internal/server/server.go` | ~1586 | 登录/2FA/vhost/Referer/route-cookie/default_service/root_absolute/files 等 |
| `internal/config/user.go` | ~1051 | 用户配置加载、校验、序列化、服务模型 |
| `main.go` | ~753 | CLI、serve、用户管理、SSO、选项解析 |

**问题：** 功能正确且配套测试较多，但认知负担高。后续改任一裸路径兼容规则，容易漏掉相邻分支（历史「闪回」类问题多半出在这类交叉路径上）。

**建议（中期拆分，不必一次做完）：**

1. `server`：`auth_handlers.go` / `proxy_routing.go` / `vhost.go` / `files_service.go`
2. `config`：服务模型与校验、序列化、registry 读写分开
3. `main`：子命令各文件（`cmd_serve.go`、`cmd_user.go`、`cmd_sso.go`）

拆分时应保持现有测试绿，优先「物理拆文件、不改行为」。

---

## 5. Minor（可排入 backlog）

### M-1. 仍接受旧版无盐 SHA-256 密码哈希

**证据：** `internal/auth/auth.go` → `VerifyPassword`

新账号与重置密码已用 bcrypt；对 64 位 hex 仍走 legacy 路径，兼容合理。长期建议：登录成功后**静默升级**为 bcrypt，并规划淘汰窗口。

---

### M-2. 默认监听 `0.0.0.0`

适合实验室共享入口；公网暴露前必须按 README / `docs/reverse-proxy-tls.md` 做 TLS 或前置反代，并正确配置 `--trusted-proxy`。文档已写清，CLI 默认值仍偏「开箱即连」——可在 `--help` 或首次 serve 日志中加强提醒。

---

### M-3. `main` 包语句覆盖率偏低（约 22.7%）

`e2e_test.go` 已存在；`serve` 启动、TLS 自签、SSO 子命令等更适合补集成测，或把可测逻辑从 `main` 抽出。`internal/*` 多数已在 60–88%，优先补 CLI/启动路径即可。

---

### M-4. 历史审核文档易与现状混淆

`docs/闪回问题审核报告.md`、`docs/修复完成报告.md` 等已标注历史存档，但仍含旧命令与路径。建议移入 `docs/archive/`，或在 README / 文档站索引中降权，避免新贡献者误读。

---

## 6. 亮点（应保留的设计基线）

### S-1. SSRF / 出站控制

**证据：** `internal/config/paths.go`、`selfloop.go`

- 写时 allowlist：仅 loopback / 私网；拒绝公网、链路本地与云元数据（如 `169.254.169.254`）。
- `SafeDialContext` 拨号时再解析并**固定已校验 IP**，缓解 DNS rebinding / TOCTOU。
- 网关自环（指向本机监听端口）在写时与拨号时双拒绝。

---

### S-2. 会话与 CSRF

**证据：** `internal/auth`、`internal/api`、`internal/proxy/cookie.go`

- Cookie：`HttpOnly` + `SameSite=Lax` + 条件 `Secure`。
- `goprox_` 命名空间：代理请求剥离网关 Cookie，后端 `Set-Cookie` 拒绝同名前缀。
- 改密使 session revision 失效，旧 token 无法复用。
- 管理 API 与登录 POST 做 Origin 同源检查。
- 网关页设置 `X-Frame-Options` / CSP `frame-ancestors`。

---

### S-3. 测试与发布节奏

- 测试行数接近生产代码；proxy / auth / config / files / rate 覆盖率高。
- Release workflow：tag 触发测试 → 静态编译 linux/amd64+arm64 → 打包校验。
- 近期提交可见持续的安全与路由边缘加固（限流饱和保护、文件锁、登出/Referer 等）。

---

## 7. 建议路线图

### 短期（1–2 周）

1. 增加 PR / `main` push 的 `go test` + `go vet` workflow。
2. 为 `files` / `auth_bootstrap` 路径增加**管理员白名单**，或限制仪表盘不可自填任意绝对路径；同步更新运维说明。
3. 登录成功后将 legacy SHA-256 哈希静默升级为 bcrypt。

### 中期

1. 拆分 `server.go`（及必要时的 `user.go` / `main.go`），先搬文件不改行为。
2. 提高 `main`/serve 启动与 TLS/SSO 路径测试覆盖。
3. 归档历史修复报告，文档站与 README 只链现行说明。

---

## 8. 审查范围与局限

**已覆盖：**

- 核心包结构与请求流
- 认证、会话、CSRF、出站 allowlist、自环、files 路径遍历防护（`os.Root`）
- 测试布局、覆盖率抽样、CI workflow
- README / 示例配置 / 部分 docs

**未覆盖：**

- 公网或内网渗透测试、模糊测试
- 生产环境配置审计（本机 `config/state.yaml` 含密钥，已 gitignore，勿提交）
- 前端 UX / 无障碍专项
- macOS 构建（项目有意仅支持 Linux 服务端场景）

**备注：** 工作区可能存在本地构建产物 `goprox` 二进制（已在 `.gitignore`）；分享仓库或发 PR 前请确认未纳入版本库。

---

## 9. 给审阅者的阅读建议

| 角色 | 建议关注章节 |
|---|---|
| 技术负责人 / 安全 | §4 I-1、§6 S-1/S-2、§7 短期第 2 条 |
| 维护者 / 贡献者 | §4 I-2/I-3、§5 M-3/M-4、§2.2 覆盖率表 |
| 运维 | §4 I-1 建议第 3 条、§5 M-2、公网 TLS 文档 |

对结论有异议时，请直接标注条目编号（如 `I-1`）并附复现或反证路径，便于跟进修订本报告。

---

## 10. 维护者核验记录（2026-11-07）

本节由维护者补充，用于说明对上述条目的复核结论与处理状态。原始条目内容未改动。

### 复核方法

- 复跑 `go test ./... -cover` 与 `wc -l`：§2.2 的覆盖率与 LOC 数据与仓库逐位一致
  （仅 `rate` 现为 89.6%，原报告 88.3%，属测量漂移）；
- 对安全条目做**真实利用验证**（临时实例 + 普通账号），不只看代码；
- 对证据路径逐条 `grep` 复核。

### 逐条结论

| 条目 | 结论 | 处理 |
|---|---|---|
| I-1 多租户本机路径权限 | **成立，且比报告更严重** | 已修：`kind: files` 的 `root` 禁止等于/包含/位于网关配置目录内（`EvalSymlinks` 后判断，符号链接无法绕过），加载时跳过并告警、API 返回 400（v0.9.1）。另补 `server.files_roots` 管理员白名单（子目录可、符号链接逃逸拒绝）。**仍保留**：「进程可读即用户可读」的整体模型未变，部署侧仍需最小权限账号 |
| I-2 缺 PR CI | 成立 | 已修：`.github/workflows/ci.yml`（`push: main` + 所有 PR，`gofmt -l` / `go vet` / `go test -race`） |
| I-3 超大文件 | 成立 | 已处理：`server.go`(1586) → 4 个领域文件、`config/user.go`(1051) → 3 个、`main.go`(753) → 5 个；纯搬移不改行为，函数数逐一核对 |
| M-1 旧 SHA-256 哈希 | 成立 | 已修：登录成功时静默升级为 bcrypt（写失败不阻塞登录；session/pending-2FA 令牌用新 revision） |
| M-2 默认监听 `0.0.0.0` | 成立 | 已处理：保留默认（实验室共享入口的产品选择），但「全接口 + 纯 HTTP + 无 trusted_proxy」启动时打印明确 WARNING |
| M-3 `main` 覆盖偏低 | 成立 | 已改善：22.7% → 40.6%（选项解析/监听覆盖/暴露面提醒/check/SSO 参数等）；`serve` 启动与 TLS 路径的集成测试仍在 backlog |
| M-4 历史文档混淆 | 成立 | 已修：四份历史报告移入 `docs/archive/`，并加归档索引 |
| S-1/S-2/S-3 亮点 | 抽查一致 | — |

### 对原文的两处修正

1. **I-1 的 `auth_bootstrap` 分支**：`token_file` / `token_log` 不在 `/api/services` 与仪表盘
   字段中，只能写 YAML，因此需要配置目录写权限（管理员），不是任意登录用户可达。用户面
   可达的只有 `kind: files` 的 `root`。
2. **I-1 的实际后果**：不止「横向读盘」。实测普通账号可下载 `state.yaml` 的
   `session_secret` 与 `users/*.yaml` 的密码哈希/TOTP 密钥，`rev = sha256(hash)[:8]`
   可离线计算，因此可**伪造任意账号会话**（网关完全接管）。修复见 v0.9.1。
