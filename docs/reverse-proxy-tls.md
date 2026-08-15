# 公网部署：反向代理终结 TLS

GoProx 本身只监听 HTTP，暴露到公网前**必须在前面放一个反向代理做 TLS 终结**，
否则密码（以及将来可能的动态码）会明文传输。

推荐 **Caddy**（两行配置、Let's Encrypt 证书自动申请与续期），或用 nginx。

## 1. 让 GoProx 只监听本机回环

反代和 GoProx 跑在同一台机器时，把网关绑定到 `127.0.0.1`，让公网**无法绕过反代直连 HTTP**：

```bash
./goprox serve --host 127.0.0.1 --port 1908 \
  --trusted-proxy 127.0.0.1/32
```

- `--host 127.0.0.1`：只监听回环，只有本机的反代能连到它（也可以用防火墙只放行 1908 给反代）
- `--trusted-proxy 127.0.0.1/32`：信任来自回环的 `X-Forwarded-For` / `X-Forwarded-Proto` 头，
  这样 GoProx 才能正确识别「真实客户端 IP」（登录限速用）和「请求是 HTTPS」（Secure Cookie 用）

> ⚠️ `--trusted-proxy` 必须填**反代所在地址**，不能填 `0.0.0.0/0`（那样任何直连客户端都能伪造 X-Forwarded-* 头，绕过限速、伪造 Secure Cookie）。

## 2. Caddy（推荐）

`/etc/caddy/Caddyfile`：

```
lab.example.com {
    reverse_proxy 127.0.0.1:1908
}
```

Caddy 会**自动**转发 `X-Forwarded-For` / `X-Forwarded-Proto`，并自动申请、续期 HTTPS 证书。
启动：`sudo systemctl reload caddy`。

## 3. nginx

`/etc/nginx/sites-available/goprox`：

```nginx
server {
    listen 443 ssl;
    server_name lab.example.com;

    ssl_certificate     /etc/letsencrypt/live/lab.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/lab.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:1908;

        proxy_set_header X-Forwarded-For   $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host  $host;

        # WebSocket（Jupyter / RStudio 必需）
        proxy_set_header Upgrade    $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
    }
}
```

证书可用 certbot 申请：`sudo certbot --nginx -d lab.example.com`。

## 4. 验证

```bash
curl -I https://lab.example.com/login     # 应返回 200，且证书有效
tail -f <goprox 日志>                       # 登录时应能看到真实客户端 IP（而非 127.0.0.1）
```

登录页在浏览器里应有正常的小锁图标（HTTPS），且登录后的 Cookie 带有 `Secure` 标记。
