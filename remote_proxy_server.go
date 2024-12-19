package main

import (
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
}

func (proxy *remoteProxyServer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Header.Get(headerSecret) == proxy.secretKey {
		proxy.serveAsDynamicReversedProxy(rw, req)
		return
	}

	proxy.serveAsStaticReversedProxy(rw, req)
}

func (proxy *remoteProxyServer) serveAsDynamicReversedProxy(rw http.ResponseWriter, req *http.Request) {
	req.Header.Del(headerSecret)
	targetAddr := appendPort(req.Host, req.URL.Scheme)

	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusServiceUnavailable)
		return
	}

	localProxy, _, _ := rw.(http.Hijacker).Hijack()

	if req.Method == http.MethodConnect {
		localProxy.Write([]byte(fmt.Sprintf("%s 200 OK\r\n\r\n", req.Proto)))
	} else {
		req.Write(target)
	}

	go transfer(localProxy, target)
	transfer(target, localProxy)
}

func (proxy *remoteProxyServer) serveAsStaticReversedProxy(rw http.ResponseWriter, req *http.Request) {
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
