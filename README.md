# sandwich-system-proxy

sandwich-system-proxy 是一个使用傻瓜化、实现简单粗暴、反深度检测、基于 HTTPS 协议、使用 IP 段分流的科学上网工具。

# 启动本地代理服务

```bash
./sandwich-system-proxy start-local-proxy-server \
 --listen-addr=:1186 \
 --remote-proxy-addr=https://yourdomain.com \
 --secret-key=<your secret key>
```

目前只支持 macOS，Windows 自动设置系统代理地址为 [http://127.0.0.1:1186](http://127.0.0.1:1186)（HTTP/HTTPS 与 SOCKS 一并指向同一端口），其他操作系统的系统代理地址需自行手动设置。

# SOCKS5

本地代理服务同一个端口同时支持 HTTP 代理和 SOCKS5 代理（通过首字节协议嗅探区分，无需额外端口和配置，SOCKS5 恒开启）。SOCKS5 仅支持 CONNECT 命令、仅支持无认证方式，不提供 UDP relay。macOS/Windows 的系统代理默认同时指向该端口（HTTP/HTTPS 与 SOCKS 都设为同一地址；其他系统需自行手动设置）。

只认 SOCKS5 的应用（如部分终端工具、即时通信软件）可以按如下方式配置：

```bash
# 建议使用 socks5h（域名交由 local 代理做 DNS 分流）
export ALL_PROXY=socks5h://127.0.0.1:1186
```

注意：为 local 代理设置非 [回环地址](https://zh.wikipedia.org/wiki/%E5%9B%9E%E7%8E%AF%E5%9C%B0%E5%9D%80)时，HTTP 和 SOCKS5 都会在无认证的情况下暴露，请自行确保网络可信。


# 启动远程代理服务

sandwich-system-proxy 会自动从 Let's Encrypt 申请、更新证书，为了使用 [TLS-ALPN-01](https://letsencrypt.org/docs/challenge-types/#tls-alpn-01) 验证，需要保证 443 端口可使用，并且必须指定 --domain 参数。

```bash
./sandwich-system-proxy start-remote-proxy-server \
 --domain=yourdomain.com \
 --secret-key=<your secret key>
```