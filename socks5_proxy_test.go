package main

import (
	"bufio"
	"bytes"
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
	return &localProxyServer{
		remoteProxyAddr:           u,
		secretKey:                 "test-secret-key",
		chinaIPRangeDB:            newChinaIPRangeDB(),
		forceForwardToRemoteProxy: forceForwardToRemoteProxy,
		client:                    &http.Client{},
		dns:                       dnsResolver,
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

// mockRemoteProxy 记录收到的 CONNECT 请求头，并回 200 OK；随后进入 echo 模式。
func mockRemoteProxy(t *testing.T, responseHead string) (addr string, captured chan string) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.Nil(t, err)
	captured = make(chan string, 1)

	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		br := bufio.NewReader(conn)
		var head bytes.Buffer
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			head.WriteString(line)
			if line == "\r\n" {
				break
			}
		}
		captured <- head.String()

		if _, err := io.WriteString(conn, responseHead); err != nil {
			return
		}
		if strings.HasPrefix(responseHead, "HTTP/1.1 200") {
			_, _ = io.Copy(conn, conn)
		}
	}()

	return ln.Addr().String(), captured
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

	// HTTP 代理（首字节非 0x05）
	proxyURL, err := url.Parse("http://" + addr)
	require.Nil(t, err)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(origin.URL)
	require.Nil(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.Nil(t, err)
	require.Equal(t, originBody, string(body))

	// SOCKS5（首字节 0x05）
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
	remoteAddr, captured := mockRemoteProxy(t, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

	local := newTestLocalProxy(&fakeDNS{ip: net.ParseIP("198.51.100.1")}, "http://"+remoteAddr, false)
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
	case head := <-captured:
		require.Contains(t, head, "CONNECT example.com:443 HTTP/1.1")
		require.Contains(t, head, "Host: example.com:443")
		require.Contains(t, head, "Misha-Secret: test-secret-key")
	case <-time.After(5 * time.Second):
		t.Fatal("remote proxy did not receive the CONNECT request")
	}
}

func TestSOCKS5ConnectRemoteNon200(t *testing.T) {
	remoteAddr, _ := mockRemoteProxy(t, "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")

	local := newTestLocalProxy(&fakeDNS{ip: net.ParseIP("198.51.100.1")}, "http://"+remoteAddr, false)
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
	remoteAddr, captured := mockRemoteProxy(t, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

	// 127.0.0.1 属私网本应直连，force-forward 后仍走 remote
	local := newTestLocalProxy(&fakeDNS{ip: net.ParseIP("127.0.0.1")}, "http://"+remoteAddr, true)
	addr := startSniffProxy(t, local)

	conn := doSOCKS5Connect(t, addr, 0x01, []byte{127, 0, 0, 1}, originPort)
	defer conn.Close()

	select {
	case head := <-captured:
		require.Contains(t, head, fmt.Sprintf("CONNECT 127.0.0.1:%d", originPort))
	case <-time.After(5 * time.Second):
		t.Fatal("remote proxy did not receive the forced CONNECT request")
	}
}

func TestSOCKS5IPv4LiteralUsesRemotePath(t *testing.T) {
	remoteAddr, captured := mockRemoteProxy(t, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

	local := newTestLocalProxy(&fakeDNS{ip: net.ParseIP("198.51.100.1")}, "http://"+remoteAddr, false)
	addr := startSniffProxy(t, local)

	conn := doSOCKS5Connect(t, addr, 0x01, []byte{198, 51, 100, 1}, 443)
	defer conn.Close()

	select {
	case head := <-captured:
		require.Contains(t, head, "CONNECT 198.51.100.1:443")
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

	// example.com 被解析为 127.0.0.1（私网，走直连）；若仍按域名 net.Dial 则必然失败
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
