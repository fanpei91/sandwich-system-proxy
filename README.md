# sandwich-system-proxy

sandwich-system-proxy 是一个使用傻瓜化、实现简单粗暴、反深度检测、基于 HTTPS/QUIC 协议、使用 IP 段分流的科学上网工具。

本地代理与远程代理之间默认优先使用 QUIC（UDP 443），QUIC 不可用时自动回退到原来的 HTTPS（TCP 443）协议，功能不受影响。远程代理的 TCP 443 行为保持不变：旧的本地代理仍可直连；浏览器无论走 TCP 还是 UDP，看到的都是一个普通网站。

# 启动本地代理服务

```bash
./sandwich-system-proxy start-local-proxy-server \
 --listen-addr=:1186 \
 --remote-proxy-addr=https://yourdomain.com \
 --secret-key=<your secret key>
```

`--remote-proxy-transport` 控制到远程代理的传输方式：

- `auto`（默认）：优先 QUIC。握手失败或超时（2s）时本次请求立即回退 HTTPS，并在 30s 起步、最长 5 分钟的退避窗口内先走 HTTPS，后台按退避探测 QUIC，恢复后自动切回。
- `quic`：只使用 QUIC，失败即报错，便于排查问题。
- `https`：只使用原来的 HTTPS（TCP 443）协议。

`--remote-proxy-addr` 必须填域名（证书校验需要 SNI），填 IP 会像以前一样校验失败。

目前只支持 macOS，Windows 自动设置系统代理地址为 [http://127.0.0.1:1186](http://127.0.0.1:1186)，其他操作系统的系统代理地址需自行手动设置。

# 启动远程代理服务

sandwich-system-proxy 会自动从 Let's Encrypt 申请、更新证书，为了使用 [TLS-ALPN-01](https://letsencrypt.org/docs/challenge-types/#tls-alpn-01) 验证，需要保证 443 端口可使用，并且必须指定 --domain 参数。

```bash
./sandwich-system-proxy start-remote-proxy-server \
 --domain=yourdomain.com \
 --secret-key=<your secret key>
```

QUIC 相关参数：

- `--enable-quic`（默认开启）：在 `--quic-listen-addr` 上同时提供 QUIC 隧道和 HTTP/3 伪装网站，两者用同一个证书。
- `--quic-listen-addr`（默认 `:443`）：QUIC 监听的 UDP 地址。UDP 绑定失败时只打日志，TCP 443 继续提供服务。

请确保防火墙/安全组放行 **UDP 443**。未放行时本地代理会自动回退 HTTPS，只是用不上 QUIC 在丢包和握手上的优势。

# 升级顺序

建议先升级远程代理，再升级本地代理，两端可以任意顺序灰度：

- 新的远程代理兼容旧的本地代理（TCP 443 协议未变）。
- 新的本地代理连不上 QUIC 时会回退 HTTPS，因此也能连旧的远程代理。
