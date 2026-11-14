package main

import (
	"bufio"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/juju/ratelimit"
)

type remoteProxyServer struct {
	secretKey              string
	staticReversedAddr     string
	enableWebsiteRatelimit bool
	outboundProxy          *socks5ProxyConfig
	outboundProxyMode      outboundProxyMode
	fallbackHosts          *fallbackHosts
}

func (proxy *remoteProxyServer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Header.Get(headerAPIKey) == proxy.secretKey {
		if req.ProtoMajor == 2 {
			proxy.forwardToTarget(rw, req)
			return
		}
		log.Printf("reject h1 request with valid X-Api-Key from %s: legacy local proxy (upgrade local and remote together)", req.RemoteAddr)
		http.Error(rw, "legacy local proxy: HTTP/1.1 tunnel removed; upgrade local and remote together", http.StatusForbidden)
		return
	}

	proxy.serveAsWebsite(rw, req)
}

func (proxy *remoteProxyServer) forwardToTarget(rw http.ResponseWriter, req *http.Request) {
	req.Header.Del(headerAPIKey)
	targetAddr := appendPort(req.Host, req.URL.Scheme)

	target, err := proxy.dialTarget(targetAddr)
	if err != nil {
		log.Printf("dial target %s error: %v", targetAddr, err)
		http.Error(rw, err.Error(), http.StatusServiceUnavailable)
		return
	}

	if req.Method == http.MethodConnect {
		rw.WriteHeader(http.StatusOK)

		var targetToClient io.Writer = rw
		flusher, _ := rw.(http.Flusher)
		if flusher != nil {
			flusher.Flush()
			targetToClient = &flushWriter{w: rw, f: flusher}
		}

		go func() {
			_, _ = io.Copy(target, req.Body)
			if cw, ok := target.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			}
		}()

		reader := &resetTrackingReader{r: target}
		n, _ := io.Copy(targetToClient, reader)
		if n == 0 && reader.reset {
			proxy.fallbackHosts.add(targetAddr)
		}
		_ = target.Close()
		return
	}

	defer target.Close()
	if err := req.Write(target); err != nil {
		log.Printf("write request to origin %s error: %v", targetAddr, err)
		http.Error(rw, err.Error(), http.StatusServiceUnavailable)
		return
	}

	br := bufio.NewReader(target)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		log.Printf("read response from origin %s error: %v", targetAddr, err)
		http.Error(rw, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		if isHopByHopHeader(k) {
			continue
		}
		for _, v := range vv {
			rw.Header().Add(k, v)
		}
	}
	rw.WriteHeader(resp.StatusCode)

	flusher, _ := rw.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
		_, _ = io.Copy(&flushWriter{w: rw, f: flusher}, resp.Body)
		return
	}
	_, _ = io.Copy(rw, resp.Body)
}

func (proxy *remoteProxyServer) dialTarget(targetAddr string) (net.Conn, error) {
	if proxy.outboundProxy != nil {
		if proxy.outboundProxyMode == outboundProxyModeAlways || proxy.fallbackHosts.contains(targetAddr) {
			return dialSOCKS5(proxy.outboundProxy, targetAddr)
		}
	}
	return (&net.Dialer{Timeout: 10 * time.Second}).Dial("tcp", targetAddr)
}

type hijackedClientConn struct {
	*bufio.Reader
	conn net.Conn
}

func (c *hijackedClientConn) Close() error {
	return c.conn.Close()
}

func (c *hijackedClientConn) CloseRead() error {
	if tc, ok := c.conn.(*net.TCPConn); ok {
		return tc.CloseRead()
	}
	return nil
}

func (c *hijackedClientConn) CloseWrite() error {
	if tc, ok := c.conn.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
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
