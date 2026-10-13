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

# TLS 分片（绕过 SNI 过滤）

remote server 连往 target 的出口链路上若有 SNI 过滤，可开启分片：把首个 TLS record（ClientHello，其中含 SNI）
拆成多个 TCP 段发送，以规避浅层 SNI 检查。该功能默认关闭，相关参数：

```bash
 --enable-tls-fragment=true \   # 是否启用分片，默认 false
 --tls-fragment-count=2 \       # ClientHello 拆成几段，默认 2
 --tls-fragment-first-len=5 \   # 第一段的字节数，默认 5（仅 record 头，不含 SNI）
 --tls-fragment-delay-ms=5      # 段间延迟（毫秒），默认 5
```

若目标网络会对多个 TCP 段做重组后再检测，可调大 `--tls-fragment-count`（如 3~4）把 ClientHello 切得更碎，
代价是握手略微变慢。分片只作用于隧道内 client → target 方向的第一个记录，后续数据原样转发。

