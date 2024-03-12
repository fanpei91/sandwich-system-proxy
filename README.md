# sandwich

sandwich 是一个使用傻瓜化、实现简单粗暴、反深度检测、基于 HTTPS 协议、使用 IP 段决定流量去向的 Proxy。

# 本地端

由于 sandwich 本地端使用了 macOS 专用的命令，所以本地端代理仅支持 macOS。

```bash
./sandwich -listen-addr=:1186 \
 -remote-proxy-addr=https://<youdomain.com>:443 \
 -secret-key=YOUR-SECRET-KEY
```

# 服务端

需要 CA 签发的证书，私钥文件。推荐使用 [acme.sh](https://github.com/acmesh-official/acme.sh) 申请 Let's Encrypt 证书。sandwich 服务端使用了 daemon，所以仅支持 *nix 系统，Windows 不支持。

```bash
./sandwich-amd64-linux -cert-file=/root/.acme.sh/<youdomain.com>/fullchain.cer  \ 
 -private-key-file=/root/.acme.sh/<youdomain.com>/<youdomain.com>.key \
 -listen-addr=:443 \
 -remote-proxy-mode=true \
 -secret-key=YOUR-SECRET-KEY
```


就这么简单，仅需两步。

如果用浏览器访问 https://<youdomain.com>，出现的就是一个由 sandwich 服务端反向代理的网站内容，这就是起反深度检测的作用。被反向代理的网站默认为 [http://mirror.siena.edu/ubuntu/](http://mirror.siena.edu/ubuntu/) ，可在 sandwich 服务端上用 `-reversed-website` 参数指定。

所有支持系统代理的应用程序，比如 Slack，Chrome，Safari 之类的 HTTP/HTTPS 请求，都会发到 sandwich 本地端通过 IP 段来决定是否需要转发到 sandwich 服务端进行代理。

如果你用的程序不支持系统代理，但支持手动设置，可手动设置程序的 HTTP/HTTPS 代理为 sandwich 本地端监听地址。对于两者都不支持的应用程序，比如 ssh 命令行程序，可使用 Proxifier 来强制它走 sandwish 本地端。
