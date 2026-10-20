package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/juju/ratelimit"
)

type remoteProxyServer struct {
	secretKey              string
	staticReversedAddr     string
	enableWebsiteRatelimit bool
	outboundProxy          *socks5ProxyConfig
	fallbackHosts          *fallbackHosts
}

func (proxy *remoteProxyServer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Header.Get(headerSecret) == proxy.secretKey {
		proxy.forwardToTarget(rw, req)
		return
	}

	proxy.serveAsWebsite(rw, req)
}

func (proxy *remoteProxyServer) forwardToTarget(rw http.ResponseWriter, req *http.Request) {
	req.Header.Del(headerSecret)
	targetAddr := appendPort(req.Host, req.URL.Scheme)

	target, err := proxy.dialTarget(targetAddr)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusServiceUnavailable)
		return
	}

	localProxy, buffered, _ := rw.(http.Hijacker).Hijack()

	isConnect := req.Method == http.MethodConnect
	if isConnect {
		localProxy.Write([]byte(fmt.Sprintf("%s 200 OK\r\n\r\n", req.Proto)))
	} else {
		req.Write(target)
	}

	client := &hijackedClientConn{Reader: buffered.Reader, conn: localProxy}

	go func() {
		reader := &resetTrackingReader{r: target}
		n, _ := io.Copy(localProxy, reader)
		if isConnect && n == 0 && reader.reset {
			proxy.fallbackHosts.add(targetAddr)
		}
		target.Close()
		localProxy.Close()
	}()

	transfer(target, client)
}

func (proxy *remoteProxyServer) dialTarget(targetAddr string) (net.Conn, error) {
	if proxy.outboundProxy != nil && proxy.fallbackHosts.contains(targetAddr) {
		return dialSOCKS5(proxy.outboundProxy, targetAddr)
	}
	return net.Dial("tcp", targetAddr)
}

type hijackedClientConn struct {
	*bufio.Reader
	conn net.Conn
}

func (c *hijackedClientConn) Close() error {
	return c.conn.Close()
}

func (proxy *remoteProxyServer) serveAsWebsite(rw http.ResponseWriter, req *http.Request) {
	var u *url.URL
	var err error
	if u, err = url.Parse(proxy.staticReversedAddr); err != nil {
		log.Fatalf("error: %s", err.Error())
		return
	}

	req.URL.Host = u.Host
	req.URL.Scheme = u.Scheme
	req.Host = ""

	if req.URL.Path == "/robots.txt" {
		rw.Write([]byte("User-agent: *\nDisallow: /"))
		return
	}

	if proxy.enableWebsiteRatelimit {
		rw = newRatelimitResponseWriter(rw)
	}

	// 懒得为伪装网站提供内容，所以就扮演一个网站代理，把 proxy.staticReversedAddr 的内容返回给浏览者
	httputil.NewSingleHostReverseProxy(u).ServeHTTP(rw, req)
}

type ratelimitResponseWriter struct {
	rw      http.ResponseWriter
	limiter io.Writer
}

func newRatelimitResponseWriter(rw http.ResponseWriter) http.ResponseWriter {
	const defaultRate = 24 * 1024
	const defaultCapacity = defaultRate * 2
	bucket := ratelimit.NewBucketWithRate(defaultRate, defaultCapacity)
	w := ratelimit.Writer(rw, bucket)
	return &ratelimitResponseWriter{
		rw:      rw,
		limiter: w,
	}
}

func (r *ratelimitResponseWriter) Header() http.Header {
	return r.rw.Header()
}

func (r *ratelimitResponseWriter) Write(p []byte) (int, error) {
	return r.limiter.Write(p)
}

func (r *ratelimitResponseWriter) WriteHeader(statusCode int) {
	r.rw.WriteHeader(statusCode)
}
