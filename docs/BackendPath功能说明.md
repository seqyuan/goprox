# BackendPath 功能说明

## 问题背景

之前的版本中，`Path` 字段只能用于前端路由（例如 `/jupyter`），但无法指定后端服务的实际路径。

当后端服务监听在特定路径上（例如 `/app/index.html`）时，代理会将请求转发到 `http://backend:port/`，而不是 `http://backend:port/app/index.html`，导致 404 错误。

## 解决方案

新增 `backend_path` 字段，用于指定后端服务的实际路径。

## 配置示例

### 示例 1: 后端是一个 HTML 文件

```yaml
services:
  - id: my-app
    name: "我的应用"
    host: "127.0.0.1"
    port: 8080
    path: "/myapp"              # 前端访问路径
    backend_path: "/app/index.html"  # 后端实际路径
    websocket: false
```

访问流程：
- 用户访问：`http://goprox-host/myapp`
- 代理转发到：`http://127.0.0.1:8080/app/index.html`

### 示例 2: 后端是一个文件夹

```yaml
services:
  - id: docs
    name: "文档站点"
    host: "127.0.0.1"
    port: 9000
    path: "/docs"
    backend_path: "/public/documentation/"
    websocket: false
```

访问流程：
- 用户访问：`http://goprox-host/docs/guide.html`
- 代理转发到：`http://127.0.0.1:9000/public/documentation/guide.html`

### 示例 3: 不使用 backend_path（默认行为）

```yaml
services:
  - id: jupyter
    name: "Jupyter Lab"
    host: "127.0.0.1"
    port: 8888
    path: "/jupyter"
    websocket: true
```

访问流程：
- 用户访问：`http://goprox-host/jupyter/lab`
- 代理转发到：`http://127.0.0.1:8888/lab`（直接去掉前端路径前缀）

## Web UI 使用

1. 添加服务时，会看到新的"后端路径"字段
2. 该字段为可选，留空则使用默认行为（直接转发）
3. 填写后端路径时：
   - 可以是文件：`/app/index.html`
   - 可以是目录：`/public/docs/`
   - 以 `/` 开头

## 技术细节

### 路径重写逻辑

在 `internal/proxy/proxy.go` 中的 `Director` 函数：

```go
if svc.BackendPath != "" {
    // 使用指定的后端路径
    targetReq.URL.Path = singleJoiningSlash(svc.BackendPath, suffix)
} else {
    // 默认行为：直接使用 suffix
    targetReq.URL.Path = suffix
}
```

### 路径处理示例

假设：
- `path = "/myapp"`
- `backend_path = "/static/app/index.html"`
- 用户请求：`/myapp/assets/style.css`

处理过程：
1. 提取 suffix：`/assets/style.css`
2. 重写为：`/static/app/index.html/assets/style.css`
3. 转发到后端

### WebSocket 支持

WebSocket 连接同样支持 `backend_path`：

```yaml
services:
  - id: terminal
    name: "Web Terminal"
    host: "127.0.0.1"
    port: 7681
    path: "/terminal"
    backend_path: "/ws/shell"
    websocket: true
```

WebSocket 升级请求会被正确转发到 `ws://127.0.0.1:7681/ws/shell`

## 与其他修复的配合

此功能与其他闪回问题修复配合使用：

1. **Session 刷新机制**：即使使用 backend_path，session 也会正常刷新
2. **Route Cookie 作用域**：backend_path 不影响 cookie 的路径范围
3. **健康检查**：会对 `backend_path` 指定的路径进行健康检查

## 注意事项

1. `backend_path` 必须以 `/` 开头
2. 如果后端服务期望特定的路径前缀，务必设置 `backend_path`
3. 对于标准的 SPA 应用，通常不需要设置 `backend_path`
4. 对于嵌套在子路径的静态站点，建议设置 `backend_path`

## 配置验证

修改配置后，可以通过以下方式验证：

```bash
# 查看日志中的代理转发信息
tail -f /path/to/goprox.log | grep "Proxying request"

# 或使用 curl 测试
curl -v http://goprox-host/myapp
```

日志中会显示：
```
Proxying request: /myapp -> http://127.0.0.1:8080/app/index.html
```
