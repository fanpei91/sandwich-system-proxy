package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type localProxyServer struct {
	remoteProxyAddr           *url.URL
	secretKey                 string
	chinaIPRangeDB            *iPRangeDB
	forceForwardToRemoteProxy bool
	client                    *http.Client
	dns                       dnsResovler
	tunnel                    *tunnelClient
}

func (proxy *localProxyServer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	targetAddr := appendPort(req.Host, req.URL.Scheme)
	host, port, _ := net.SplitHostPort(targetAddr)

	if proxy.forceForwardToRemoteProxy {
		proxy.forwardToRemoteProxy(rw, req)
		return
	}

	targetIP, err := proxy.resolveTargetIP(host)
	if err != nil {
		log.Printf("resolve %s error: %v", host, err)
		http.Error(rw, fmt.Sprintf("lookup %s: no such host", host), http.StatusServiceUnavailable)
		return
	}

	if !proxy.useRemoteProxy(targetIP) {
		log.Println(fmt.Sprintf("origin <-> local <-> %s(%s)", host, targetIP))
		proxy.forwardToTarget(rw, req, net.JoinHostPort(targetIP.String(), port))
		return
	}

	log.Println(fmt.Sprintf("origin <-> local <-> remote <-> %s(%s)", host, targetIP))
	proxy.forwardToRemoteProxy(rw, req)
}

func (proxy *localProxyServer) resolveTargetIP(host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip, nil
	}
	err, targetIP, _ := proxy.dns.lookup(host)
	if err != nil {
		return nil, err
	}
	if targetIP == nil {
		return nil, fmt.Errorf("no answer for %s", host)
	}
	return targetIP, nil
}

func (proxy *localProxyServer) useRemoteProxy(targetIP net.IP) bool {
	if proxy.forceForwardToRemoteProxy {
		return true
	}
	return !(proxy.chinaIPRangeDB.contains(targetIP) || privateIPRange.contains(targetIP))
}

func (proxy *localProxyServer) forwardToTarget(rw http.ResponseWriter, req *http.Request, targetAddr string) {
	client, buffered, err := rw.(http.Hijacker).Hijack()
	if err != nil {
		log.Printf("hijack failed for %s %s: %v", req.Method, req.Host, err)
		return
	}
	target, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		log.Printf("dial target %s error: %v", targetAddr, err)
		fmt.Fprintf(client, "HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n503 dial target %s: %v\r\n", targetAddr, err)
		_ = client.Close()
		return
	}

	if req.Method == http.MethodConnect {
		client.Write([]byte(fmt.Sprintf("%s 200 OK\r\n\r\n", req.Proto)))
	} else {
		if v := req.Header.Get("Proxy-Connection"); v != "" {
			req.Header.Del("Proxy-Connection")
			req.Header.Set("Connection", v)
		}
		req.Write(target)
	}

	go transfer(client, target)
	transfer(target, &hijackedClientConn{Reader: buffered.Reader, conn: client})
}

func (proxy *localProxyServer) forwardToRemoteProxy(rw http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodConnect {
		proxy.forwardConnectToRemoteProxy(rw, req)
		return
	}
	proxy.forwardPlainHTTPToRemoteProxy(rw, req)
}

func (proxy *localProxyServer) forwardConnectToRemoteProxy(rw http.ResponseWriter, req *http.Request) {
	client, buffered, err := rw.(http.Hijacker).Hijack()
	if err != nil {
		log.Printf("hijack failed for CONNECT %s: %v", req.Host, err)
		return
	}

	tunnel, err := proxy.tunnel.ConnectTunnel(context.Background(), req.Host)
	if err != nil {
		log.Printf("h2 tunnel to remote proxy for CONNECT %s failed: %v (local and remote must be upgraded together)", req.Host, err)
		fmt.Fprintf(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n502 Bad Gateway: cannot open an HTTP/2 tunnel to the remote proxy (%v).\r\nThe remote proxy must support the HTTP/2 CONNECT tunnel; upgrade local and remote together.\r\n", err)
		_ = client.Close()
		return
	}

	if _, err := fmt.Fprintf(client, "%s 200 OK\r\n\r\n", req.Proto); err != nil {
		log.Printf("write CONNECT response to client for %s: %v", req.Host, err)
		_ = tunnel.Close()
		_ = client.Close()
		return
	}

	go transfer(tunnel, &hijackedClientConn{Reader: buffered.Reader, conn: client})
	transfer(client, tunnel)
}

func (proxy *localProxyServer) forwardPlainHTTPToRemoteProxy(rw http.ResponseWriter, req *http.Request) {
	targetScheme := req.URL.Scheme
	if targetScheme == "" {
		targetScheme = "http"
	}
	targetHost := req.URL.Host
	if targetHost == "" {
		targetHost = req.Host
	}

	fwd := &http.Request{
		Method: req.Method,
		URL: &url.URL{
			Scheme:   targetScheme,
			Host:     targetHost,
			Path:     req.URL.Path,
			RawPath:  req.URL.RawPath,
			RawQuery: req.URL.RawQuery,
		},
		Header:        filterHopByHop(req.Header),
		Body:          req.Body,
		ContentLength: req.ContentLength,
		Host:          req.Host,
	}
	fwd = fwd.WithContext(req.Context())

	resp, err := proxy.tunnel.RoundTrip(fwd)
	if err != nil {
		log.Printf("h2 forward of %s %s via remote proxy failed: %v (local and remote must be upgraded together)", req.Method, targetHost, err)
		http.Error(rw, fmt.Sprintf("502 Bad Gateway: cannot reach the remote proxy over HTTP/2 (%v). The remote proxy must support the HTTP/2 tunnel; upgrade local and remote together.", err), http.StatusBadGateway)
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
		_, _ = io.Copy(&flushWriter{w: rw, f: flusher}, resp.Body)
		return
	}
	_, _ = io.Copy(rw, resp.Body)
}

func (proxy *localProxyServer) pullLatestIPRange(ctx context.Context) error {
	addr := "https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, addr, nil)
	res, err := proxy.client.Do(req)
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return err
	}

	reader := bufio.NewReader(res.Body)
	var line []byte
	var db []*ipRange
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		if line, _, err = reader.ReadLine(); err != nil && err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		if len(line) == 0 || line[0] == '#' {
			continue
		}

		parts := strings.SplitN(string(line), "|", 6)
		if len(parts) != 6 {
			continue
		}

		cc, typ, start, value := parts[1], parts[2], parts[3], parts[4]
		if !(cc == "CN" && (typ == "ipv4" || typ == "ipv6")) {
			continue
		}

		prefixLength, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		if typ == "ipv4" {
			prefixLength = 32 - int(math.Log(float64(prefixLength))/math.Log(2))
		}

		db = append(db, &ipRange{value: fmt.Sprintf("%s/%d", start, prefixLength)})
	}

	if len(db) == 0 {
		return errors.New("empty ip range db")
	}

	proxy.chinaIPRangeDB.Lock()
	defer proxy.chinaIPRangeDB.Unlock()
	proxy.chinaIPRangeDB.db = db
	proxy.chinaIPRangeDB.init()
	sort.Sort(proxy.chinaIPRangeDB)
	return nil
}

type closeWriteCloser interface{ CloseWrite() error }
type closeReadCloser interface{ CloseRead() error }

func transfer(dst io.WriteCloser, src io.ReadCloser) {
	defer func() {
		if cw, ok := dst.(closeWriteCloser); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}()
	defer func() {
		if cr, ok := src.(closeReadCloser); ok {
			_ = cr.CloseRead()
		} else {
			_ = src.Close()
		}
	}()
	io.Copy(dst, src)
}

func appendPort(host string, schema string) string {
	if strings.Index(host, ":") < 0 || strings.HasSuffix(host, "]") {
		if schema == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	return host
}
