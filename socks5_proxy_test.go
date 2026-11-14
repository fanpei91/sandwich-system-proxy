package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fakeDNS struct {
	ip  net.IP
	err error
}

func (d *fakeDNS) lookup(host string) (error, net.IP, time.Time) {
	return d.err, d.ip, time.Now()
}

func (d *fakeDNS) name() string {
	return "fakeDNS"
}

func newTestLocalProxy(dnsResolver dnsResovler, remoteProxyAddr string, forceForwardToRemoteProxy bool) *localProxyServer {
	u, err := url.Parse(remoteProxyAddr)
	if err != nil {
		panic(err)
	}
	tunnel := newTunnelClient(appendPort(u.Host, u.Scheme), u.Scheme, "test-secret-key", 2, &tls.Config{InsecureSkipVerify: true})
	return &localProxyServer{
		remoteProxyAddr:           u,
		secretKey:                 "test-secret-key",
		chinaIPRangeDB:            newChinaIPRangeDB(),
		forceForwardToRemoteProxy: forceForwardToRemoteProxy,
		client:                    &http.Client{},
		dns:                       dnsResolver,
		tunnel:                    tunnel,
	}
}

func startSniffProxy(t *testing.T, local *localProxyServer) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.Nil(t, err)

	sniff := &sniffingListener{Listener: ln, handleSOCKS5: local.serveSOCKS5}
	go func() { _ = http.Serve(sniff, local) }()
	t.Cleanup(func() { _ = ln.Close() })

	return ln.Addr().String()
}

func mockH2RemoteProxy(t *testing.T, handler http.HandlerFunc) (addr string, captured chan *http.Request) {
	t.Helper()

	captured = make(chan *http.Request, 64)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case captured <- r:
		default:
		}
		handler(w, r)
	})

	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return strings.TrimPrefix(srv.URL, "https://"), captured
}

func h2TunnelEchoHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	if flusher == nil {
		_, _ = io.Copy(w, r.Body)
		return
	}
	flusher.Flush()
	_, _ = io.Copy(&flushWriter{w: w, f: flusher}, r.Body)
}

func doSOCKS5Handshake(t *testing.T, conn net.Conn, cmd byte, atyp byte, addr []byte, port uint16) byte {
	t.Helper()

	_, err := conn.Write([]byte{0x05, 0x01, 0x00})
	require.Nil(t, err)
	greeting := make([]byte, 2)
	_, err = io.ReadFull(conn, greeting)
	require.Nil(t, err)
	require.Equal(t, []byte{0x05, 0x00}, greeting)

	req := []byte{0x05, cmd, 0x00, atyp}
	req = append(req, addr...)
	req = append(req, byte(port>>8), byte(port))
	_, err = conn.Write(req)
	require.Nil(t, err)

	resp := make([]byte, 10)
	_, err = io.ReadFull(conn, resp)
	require.Nil(t, err)
	require.Equal(t, byte(0x05), resp[0])
	require.Equal(t, byte(0x00), resp[2])

	return resp[1]
}

func doSOCKS5Connect(t *testing.T, addr string, atyp byte, addrBytes []byte, port uint16) net.Conn {
	t.Helper()

	conn, err := net.Dial("tcp", addr)
	require.Nil(t, err)
	rep := doSOCKS5Handshake(t, conn, 0x01, atyp, addrBytes, port)
	require.Equal(t, byte(0x00), rep)
	return conn
}

func splitHostPort(t *testing.T, addr string) (string, uint16) {
	t.Helper()

	host, port, err := net.SplitHostPort(addr)
	require.Nil(t, err)
	p, err := strconv.ParseUint(port, 10, 16)
	require.Nil(t, err)
	return host, uint16(p)
}

func domainAddr(host string) []byte {
	return append([]byte{byte(len(host))}, []byte(host)...)
}

func TestSOCKS5AndHTTPOnSamePort(t *testing.T) {
	originBody := "hello-origin"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(originBody))
	}))
	defer origin.Close()

	local := newTestLocalProxy(&fakeDNS{ip: net.ParseIP("127.0.0.1")}, "http://127.0.0.1:1", false)
	addr := startSniffProxy(t, local)

	proxyURL, err := url.Parse("http://" + addr)
	require.Nil(t, err)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(origin.URL)
	require.Nil(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.Nil(t, err)
	require.Equal(t, originBody, string(body))

	conn := doSOCKS5Connect(t, addr, 0x01, []byte{127, 0, 0, 1}, portOf(t, origin))
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
	require.Nil(t, err)
	head, err := io.ReadAll(conn)
	require.Nil(t, err)
	require.Contains(t, string(head), "200 OK")
	require.Contains(t, string(head), originBody)
}

func TestSOCKS5ConnectDomainForwardedToRemote(t *testing.T) {
	remoteAddr, captured := mockH2RemoteProxy(t, h2TunnelEchoHandler)

	local := newTestLocalProxy(&fakeDNS{ip: net.ParseIP("198.51.100.1")}, "https://"+remoteAddr, false)
	addr := startSniffProxy(t, local)

	conn := doSOCKS5Connect(t, addr, 0x03, domainAddr("example.com"), 443)
	defer conn.Close()

	_, err := conn.Write([]byte("ping-through-tunnel"))
	require.Nil(t, err)
	echo := make([]byte, len("ping-through-tunnel"))
	_, err = io.ReadFull(conn, echo)
	require.Nil(t, err)
	require.Equal(t, "ping-through-tunnel", string(echo))

	select {
	case req := <-captured:
		require.Equal(t, http.MethodConnect, req.Method)
		require.Equal(t, "example.com:443", req.Host)
		require.Equal(t, "test-secret-key", req.Header.Get("X-Api-Key"))
	case <-time.After(5 * time.Second):
		t.Fatal("remote proxy did not receive the CONNECT request")
	}
}

func TestSOCKS5ConnectRemoteNon200(t *testing.T) {
	remoteAddr, _ := mockH2RemoteProxy(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	local := newTestLocalProxy(&fakeDNS{ip: net.ParseIP("198.51.100.1")}, "https://"+remoteAddr, false)
	addr := startSniffProxy(t, local)

	conn, err := net.Dial("tcp", addr)
	require.Nil(t, err)
	defer conn.Close()

	rep := doSOCKS5Handshake(t, conn, 0x01, 0x03, domainAddr("example.com"), 443)
	require.Equal(t, byte(0x01), rep)
}

func TestSOCKS5ConnectRemoteDialRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.Nil(t, err)
	remoteAddr := ln.Addr().String()
	require.Nil(t, ln.Close())

	local := newTestLocalProxy(&fakeDNS{ip: net.ParseIP("198.51.100.1")}, "http://"+remoteAddr, false)
	addr := startSniffProxy(t, local)

	conn, err := net.Dial("tcp", addr)
	require.Nil(t, err)
	defer conn.Close()

	rep := doSOCKS5Handshake(t, conn, 0x01, 0x03, domainAddr("example.com"), 443)
	require.Equal(t, byte(0x05), rep)
}

func TestSOCKS5DNSFailure(t *testing.T) {
	local := newTestLocalProxy(&fakeDNS{err: errors.New("lookup boom")}, "http://127.0.0.1:1", false)
	addr := startSniffProxy(t, local)

	conn, err := net.Dial("tcp", addr)
	require.Nil(t, err)
	defer conn.Close()

	rep := doSOCKS5Handshake(t, conn, 0x01, 0x03, domainAddr("example.com"), 443)
	require.Equal(t, byte(0x04), rep)
}

func TestSOCKS5UnsupportedCommands(t *testing.T) {
	local := newTestLocalProxy(&fakeDNS{ip: net.ParseIP("198.51.100.1")}, "http://127.0.0.1:1", false)
	addr := startSniffProxy(t, local)

	for _, cmd := range []byte{0x02, 0x03} {
		conn, err := net.Dial("tcp", addr)
		require.Nil(t, err)

		rep := doSOCKS5Handshake(t, conn, cmd, 0x01, []byte{127, 0, 0, 1}, 80)
		require.Equal(t, byte(0x07), rep)
		_ = conn.Close()
	}
}

func TestSOCKS5UnsupportedAddressType(t *testing.T) {
	local := newTestLocalProxy(&fakeDNS{ip: net.ParseIP("198.51.100.1")}, "http://127.0.0.1:1", false)
	addr := startSniffProxy(t, local)

	conn, err := net.Dial("tcp", addr)
	require.Nil(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	require.Nil(t, err)
	greeting := make([]byte, 2)
	_, err = io.ReadFull(conn, greeting)
	require.Nil(t, err)

	_, err = conn.Write([]byte{0x05, 0x01, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50})
	require.Nil(t, err)

	resp := make([]byte, 10)
	_, err = io.ReadFull(conn, resp)
	require.Nil(t, err)
	require.Equal(t, byte(0x08), resp[1])
}

func TestSOCKS5GreetingWithoutNoAuthMethod(t *testing.T) {
	local := newTestLocalProxy(&fakeDNS{ip: net.ParseIP("198.51.100.1")}, "http://127.0.0.1:1", false)
	addr := startSniffProxy(t, local)

	conn, err := net.Dial("tcp", addr)
	require.Nil(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte{0x05, 0x01, 0x02})
	require.Nil(t, err)

	reply := make([]byte, 2)
	_, err = io.ReadFull(conn, reply)
	require.Nil(t, err)
	require.Equal(t, []byte{0x05, 0xFF}, reply)
}

func TestSOCKS5BadGreetingVersion(t *testing.T) {
	local := newTestLocalProxy(&fakeDNS{ip: net.ParseIP("198.51.100.1")}, "http://127.0.0.1:1", false)
	addr := startSniffProxy(t, local)

	conn, err := net.Dial("tcp", addr)
	require.Nil(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte{0x04, 0x01, 0x00})
	require.Nil(t, err)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2)
	_, err = conn.Read(buf)
	require.Error(t, err)
}

func TestSOCKS5ForceForwardToRemoteProxy(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("origin-body"))
	}))
	defer origin.Close()

	_, originPort := splitHostPort(t, origin.Listener.Addr().String())
	remoteAddr, captured := mockH2RemoteProxy(t, h2TunnelEchoHandler)

	local := newTestLocalProxy(&fakeDNS{ip: net.ParseIP("127.0.0.1")}, "https://"+remoteAddr, true)
	addr := startSniffProxy(t, local)

	conn := doSOCKS5Connect(t, addr, 0x01, []byte{127, 0, 0, 1}, originPort)
	defer conn.Close()

	select {
	case req := <-captured:
		require.Equal(t, http.MethodConnect, req.Method)
		require.Equal(t, fmt.Sprintf("127.0.0.1:%d", originPort), req.Host)
	case <-time.After(5 * time.Second):
		t.Fatal("remote proxy did not receive the forced CONNECT request")
	}
}

func TestSOCKS5IPv4LiteralUsesRemotePath(t *testing.T) {
	remoteAddr, captured := mockH2RemoteProxy(t, h2TunnelEchoHandler)

	local := newTestLocalProxy(&fakeDNS{ip: net.ParseIP("198.51.100.1")}, "https://"+remoteAddr, false)
	addr := startSniffProxy(t, local)

	conn := doSOCKS5Connect(t, addr, 0x01, []byte{198, 51, 100, 1}, 443)
	defer conn.Close()

	select {
	case req := <-captured:
		require.Equal(t, http.MethodConnect, req.Method)
		require.Equal(t, "198.51.100.1:443", req.Host)
	case <-time.After(5 * time.Second):
		t.Fatal("remote proxy did not receive the CONNECT request")
	}
}

func TestSOCKS5DomainDirectDialsResolvedIP(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	require.Nil(t, err)
	defer echo.Close()

	go func() {
		conn, err := echo.Accept()
		if err != nil {
			return
		}
		_, _ = io.Copy(conn, conn)
	}()

	local := newTestLocalProxy(&fakeDNS{ip: net.ParseIP("127.0.0.1")}, "http://127.0.0.1:1", false)
	addr := startSniffProxy(t, local)
	_, echoPort := splitHostPort(t, echo.Addr().String())

	conn := doSOCKS5Connect(t, addr, 0x03, domainAddr("example.com"), echoPort)
	defer conn.Close()

	_, err = conn.Write([]byte("abc"))
	require.Nil(t, err)
	buf := make([]byte, 3)
	_, err = io.ReadFull(conn, buf)
	require.Nil(t, err)
	require.Equal(t, "abc", string(buf))
}

func TestSOCKS5IPv6LiteralDirect(t *testing.T) {
	echo, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 not available: %v", err)
	}
	defer echo.Close()

	local := newTestLocalProxy(&fakeDNS{ip: net.ParseIP("198.51.100.1")}, "http://127.0.0.1:1", false)
	addr := startSniffProxy(t, local)

	_, echoPort := splitHostPort(t, echo.Addr().String())
	conn := doSOCKS5Connect(t, addr, 0x04, net.ParseIP("::1").To16(), echoPort)
	defer conn.Close()
}

func TestHTTPProxyDirectDialsResolvedIP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.Nil(t, err)
	defer ln.Close()

	originHit := make(chan struct{}, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		originHit <- struct{}{}
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))
	}()

	local := newTestLocalProxy(&fakeDNS{ip: net.ParseIP("127.0.0.1")}, "http://127.0.0.1:1", false)
	addr := startSniffProxy(t, local)

	proxyURL, err := url.Parse("http://" + addr)
	require.Nil(t, err)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	_, originPort := splitHostPort(t, ln.Addr().String())
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://example.com:%d/", originPort), nil)
	require.Nil(t, err)
	resp, err := client.Do(req)
	require.Nil(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.Nil(t, err)
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, "ok", string(body))

	select {
	case <-originHit:
	case <-time.After(5 * time.Second):
		t.Fatal("origin did not receive the request")
	}
}

func portOf(t *testing.T, server *httptest.Server) uint16 {
	t.Helper()

	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	require.Nil(t, err)
	p, err := strconv.ParseUint(port, 10, 16)
	require.Nil(t, err)
	return uint16(p)
}
