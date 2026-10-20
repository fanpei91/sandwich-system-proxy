# sandwich-system-proxy

sandwich-system-proxy 是一个使用傻瓜化、实现简单粗暴、反深度检测、基于 HTTPS 协议、使用 IP 段分流的科学上网工具。

# 启动本地代理服务

```bash
./sandwich-system-proxy start-local-proxy-server \
 --listen-addr=:1186 \
 --remote-proxy-addr=https://yourdomain.com \
 --secret-key=<your secret key>
```

目前只支持 macOS，Windows 自动设置系统代理地址为 [http://127.0.0.1:1186](http://127.0.0.1:1186)，其他操作系统的系统代理地址需自行手动设置。

# 启动远程代理服务

sandwich-system-proxy 会自动从 Let's Encrypt 申请、更新证书，为了使用 [TLS-ALPN-01](https://letsencrypt.org/docs/challenge-types/#tls-alpn-01) 验证，需要保证 443 端口可使用，并且必须指定 --domain 参数。

```bash
./sandwich-system-proxy start-remote-proxy-server \
 --domain=yourdomain.com \
 --secret-key=<your secret key>
```

# 直连被 RST 时回退到 SOCKS5

remote server 直连 target 时，若出口设备在 TLS 握手阶段返回 RST，会断开本次连接并把该 target 记入内存
（进程内永久有效，重启清空），之后该 target 的连接改走 `--outbound-socks5-proxy` 指定的 SOCKS5 代理。客户端
（浏览器等）会自动重试，因此首次访问会多一次失败重试。

典型场景是机房对出向 HTTPS 做 SNI 过滤：设备读到 ClientHello 里的被禁 SNI 后直接返回 RST，导致直连握手失败。
此时把出口指向不受该过滤影响的 SOCKS5 代理（例如本机运行 Cloudflare WARP 提供的 SOCKS5）即可绕过。

```bash
 --outbound-socks5-proxy=socks5://user:pass@127.0.0.1:40000   # 兜底 SOCKS5，支持可选认证，默认空（不启用）
```

