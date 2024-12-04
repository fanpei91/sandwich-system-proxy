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
	secretKey          string
	staticReversedAddr string
	ecoBandwidthMode   bool
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

	if proxy.ecoBandwidthMode {
		rw = newEcoBandwidthResponseWriter(rw)
	}

	if proxy.isWebRobotRequest(req) {
		proxy.responseRobot(rw)
		return
	}

	httputil.NewSingleHostReverseProxy(u).ServeHTTP(rw, req)
}

func (proxy *remoteProxyServer) isWebRobotRequest(req *http.Request) bool {
	return req.URL.Path == "/robots.txt"
}
func (proxy *remoteProxyServer) responseRobot(rw http.ResponseWriter) {
	rw.Write([]byte("User-agent: *\nDisallow: /"))
}

type ecoBandwidthResponseWriter struct {
	rw      http.ResponseWriter
	limiter io.Writer
}

func newEcoBandwidthResponseWriter(rw http.ResponseWriter) *ecoBandwidthResponseWriter {
	const defaultRate = 24 * 1024
	const defaultCapacity = defaultRate * 2
	bucket := ratelimit.NewBucketWithRate(defaultRate, defaultCapacity)
	w := ratelimit.Writer(rw, bucket)
	return &ecoBandwidthResponseWriter{
		rw:      rw,
		limiter: w,
	}
}

func (r *ecoBandwidthResponseWriter) Header() http.Header {
	return r.rw.Header()
}

func (r *ecoBandwidthResponseWriter) Write(p []byte) (int, error) {
	return r.limiter.Write(p)
}

func (r *ecoBandwidthResponseWriter) WriteHeader(statusCode int) {
	r.rw.WriteHeader(statusCode)
}
