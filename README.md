# sandwich-system-proxy

sandwich-system-proxy 是一个傻瓜化、实现简单、伪装强、安全、基于 HTTPS 协议、使用 IP 段而不是主机规则表的智能代理。

# 启动本地代理服务

```bash
./sandwich-system-proxy start-local-proxy-server \
 --listen-addr=:1186 \
 --remote-proxy-addr=https://<youdomain.com>:443 \
 --secret-key=<your secret key>
```

目前只支持 macOS 自动设置系统代理地址为 127.0.0.1:1186，其他操作系统的系统代理地址需自行手动设置。

# 启动远程代理服务

sandwich-system-proxy 会自动从 Let's Encrypt 申请、更新证书，为了 [HTTP-01 challenges](https://letsencrypt.org/docs/challenge-types/#http-01-challenge)，需要保证 80 端口可监听。

```bash
./sandwich-system-proxy start-remote-proxy-server \
 --listen-addr=:443 \
 --secret-key=<your secret key>
```