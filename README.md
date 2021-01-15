# sandwich

sandwich 是一个傻瓜化、实现简单、伪装强、安全、基于 HTTPS 协议、使用 IP 段而不是主机规则表的智能代理。

# 本地代理

由于 sandwich 本地代理使用了 macOS 专用的命令，所以本地代理仅支持 macOS。

```bash
./sandwich -listen-addr=:1186 \
 -remote-proxy-addr=https://<youdomain.com>:443 \
 -secret-key=dcf10cfe73d1bf97f7b3
```

# 海外代理

需要 CA 签发的证书，私钥文件。推荐使用 [acme.sh](https://github.com/acmesh-official/acme.sh) 申请 Let's Encrypt 证书。sandwich 服务端代理使用了 daemon，所以仅支持 *nix 系统，windows 不支持。

```bash
./sandwich-amd64-linux -cert-file=/root/.acme.sh/<youdomain.com>/fullchain.cer  \ 
 -private-key-file=/root/.acme.sh/<youdomain.com>/<youdomain.com>.key \
 -listen-addr=:443 \
 -remote-proxy-mode=true \
 -secret-key=dcf10cfe73d1bf97f7b3
```


仅需这两步，不要其他插件。

如果用浏览器访问 https://<youdomain.com>，出现的就是一个正常普通的反向代理网站，这就是伪装强的原因。反向代理的网站默认为 [http://mirror.siena.edu/ubuntu/](http://mirror.siena.edu/ubuntu/) ，可在海外的 sandwich 上用 `-reversed-website` 参数指定。

所有支持系统代理的应用程序，比如 Slack，Chrome，Safari 之类的 HTTP/HTTPS 请求，都会发到 sandwich local proxy 通过 IP 段来决定是否需要转发到海外 sandwich 代理。

如果你用的程序不支持系统代理，但支持手动设置，可手动设置程序的 HTTP/HTTPS 代理为 sandwich local 监听地址。对于两者都不支持的应用程序，比如 ssh 命令行程序，可使用 Proxifier 来强制它走 sandwish local 代理。

# TODO
* 通过创建 Tun 虚拟网卡实现透明代理
