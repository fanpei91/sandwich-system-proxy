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

需要 CA 签发的证书，私钥文件。推荐使用 [acme.sh](https://github.com/acmesh-official/acme.sh) 申请 Let's Encrypt 证书。

```bash
./sandwich-system-proxy start-remote-proxy-server \
 --listen-addr=:443 \
 --cert-file=/root/.acme.sh/<youdomain.com>/fullchain.cer  \ 
 --private-key-file=/root/.acme.sh/<youdomain.com>/<youdomain.com>.key \
 --secret-key=<your secret key>
```

仅需这两步，不要其他插件。

如果用浏览器访问 https://<youdomain.com>，出现的就是一个正常普通的反向代理网站，这是反深度检测的最核心的手段。其被反向代理的网站默认为 [https://mirror.pilotfiber.com/ubuntu/](https://mirror.pilotfiber.com/ubuntu/) ，可在远程的 sandwich-system-proxy 上用 `--static-reversed-url` 参数指定。

所有支持系统代理自动检测的应用程序，比如 Slack，Chrome，Safari 之类的 HTTP/HTTPS 请求，都会发到 sandwich-system-proxy 的 local proxy 通过 IP 段来决定是否需要转发到远程 sandwich-system-proxy 代理。可通过指定 `--force-forward-to-remote-proxy=true` 强行转发所有请求到远程 sandwich-system-proxy。

如果你用的程序不支持系统代理自动检测，但支持手动设置，可手动设置程序的 HTTP/HTTPS 代理为 127.0.0.1:1186。对于两者都不支持的应用程序，比如 ssh 命令行程序，可使用 Proxifier 来强制它走 127.0.0.1:1186。