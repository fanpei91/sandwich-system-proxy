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

type remoteProxy struct {
	secretKey       string
	reversedWebsite string
	rateLimit       bool
}

func (s *remoteProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Header.Get(headerSecret) == s.secretKey {
		s.crossWall(rw, req)
		return
	}

	s.reverseProxy(rw, req)
}

func (s *remoteProxy) crossWall(rw http.ResponseWriter, req *http.Request) {
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

func (s *remoteProxy) reverseProxy(rw http.ResponseWriter, req *http.Request) {
	var u *url.URL
	var err error
	if u, err = url.Parse(s.reversedWebsite); err != nil {
		log.Fatalf("error: %s", err.Error())
	}

	req.URL.Host = u.Host
	req.URL.Scheme = u.Scheme
	req.Host = ""
	if s.rateLimit {
		rw = newRateLimitResponseWriter(rw)
	}
	httputil.NewSingleHostReverseProxy(u).ServeHTTP(rw, req)
}

const (
	defaultRate = 20 * 1024 // 20 KB
)

type rateLimitResponseWriter struct {
	rw      http.ResponseWriter
	limiter io.Writer
}

func newRateLimitResponseWriter(rw http.ResponseWriter) *rateLimitResponseWriter {
	bucket := ratelimit.NewBucketWithRate(defaultRate, defaultRate)
	w := ratelimit.Writer(rw, bucket)
	return &rateLimitResponseWriter{
		rw:      rw,
		limiter: w,
	}
}

func (r *rateLimitResponseWriter) Header() http.Header {
	return r.rw.Header()
}

func (r *rateLimitResponseWriter) Write(p []byte) (int, error) {
	return r.limiter.Write(p)
}

func (r *rateLimitResponseWriter) WriteHeader(statusCode int) {
	r.rw.WriteHeader(statusCode)
}

func transfer(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
}
