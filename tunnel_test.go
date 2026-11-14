package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

const testRemoteSecret = "test-secret-key"

type trackingListener struct {
	net.Listener

	mu    sync.Mutex
	conns []net.Conn
}

func (l *trackingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.mu.Lock()
		l.conns = append(l.conns, c)
		l.mu.Unlock()
	}
	return c, err
}

func (l *trackingListener) tracked() []net.Conn {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]net.Conn(nil), l.conns...)
}

func newTrackingListener(t *testing.T) *trackingListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.Nil(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	return &trackingListener{Listener: ln}
}

func newRemoteServer(remote *remoteProxyServer, ln net.Listener, nextProtos []string) *httptest.Server {
	srv := httptest.NewUnstartedServer(remote)
	if ln != nil {
		srv.Listener = ln
	}
	srv.TLS = &tls.Config{NextProtos: nextProtos}
	srv.StartTLS()
	return srv
}

func newTestRemote(secretKey string) *remoteProxyServer {
	return &remoteProxyServer{
		secretKey:              secretKey,
		staticReversedAddr:     "https://decoy.invalid",
		enableWebsiteRatelimit: false,
		fallbackHosts:          newFallbackHosts(time.Hour),
	}
}

func newRealRemote(t *testing.T, nextProtos []string) string {
	t.Helper()
	srv := newRemoteServer(newTestRemote(testRemoteSecret), nil, nextProtos)
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "https://")
}

func newForceForwardLocal(t *testing.T, remoteAddr string) string {
	t.Helper()
	local := newTestLocalProxy(&fakeDNS{ip: net.ParseIP("198.51.100.1")}, "https://"+remoteAddr, true)
	addr := startSniffProxy(t, local)
	return addr
}

func localProxyURL(addr string) *url.URL {
	u, err := url.Parse("http://" + addr)
	if err != nil {
		panic(err)
	}
	return u
}

func insecureClient(proxyAddr string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(localProxyURL(proxyAddr)),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func TestHTTPConnectViaH2Tunnel(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("origin-ok"))
	}))
	defer origin.Close()

	remoteAddr := newRealRemote(t, []string{"h2"})
	localAddr := newForceForwardLocal(t, remoteAddr)

	resp, err := insecureClient(localAddr).Get(origin.URL)
	require.Nil(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.Nil(t, err)
	require.Equal(t, "origin-ok", string(body))
}

func TestHTTPAbsoluteURIForwardViaH2Tunnel(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "forwarded-body")
		_, _ = fmt.Fprintf(w, "|uri=%s", r.RequestURI)
		_, _ = fmt.Fprintf(w, "|key=%s", r.Header.Get("X-Api-Key"))
	}))
	defer origin.Close()

	remoteAddr := newRealRemote(t, []string{"h2"})
	localAddr := newForceForwardLocal(t, remoteAddr)

	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(localProxyURL(localAddr))}}
	_, originPort := splitHostPort(t, origin.Listener.Addr().String())
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/forward/path?q=1", originPort))
	require.Nil(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.Nil(t, err)
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, "forwarded-body|uri=/forward/path?q=1|key=", string(body))
}

func TestH2TunnelHalfClose(t *testing.T) {
	echoAddr := startEchoUntilEOF(t)
	_, echoPort := splitHostPort(t, echoAddr)

	remoteAddr := newRealRemote(t, []string{"h2"})
	localAddr := newForceForwardLocal(t, remoteAddr)

	conn := doSOCKS5Connect(t, localAddr, 0x01, []byte{127, 0, 0, 1}, echoPort)
	defer conn.Close()
	_, err := conn.Write([]byte("ping"))
	require.Nil(t, err)
	conn.(*net.TCPConn).CloseWrite()
	resp, err := io.ReadAll(conn)
	require.Nil(t, err)
	require.Equal(t, "echo:ping", string(resp))

	connectConn, err := net.Dial("tcp", localAddr)
	require.Nil(t, err)
	defer connectConn.Close()
	_, err = fmt.Fprintf(connectConn, "CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", echoPort, echoPort)
	require.Nil(t, err)
	br := bufio.NewReader(connectConn)
	statusLine, err := br.ReadString('\n')
	require.Nil(t, err)
	require.True(t, strings.HasPrefix(statusLine, "HTTP/1.1 200"), "unexpected status line %q", statusLine)
	for {
		line, err := br.ReadString('\n')
		require.Nil(t, err)
		if line == "\r\n" {
			break
		}
	}
	_, err = connectConn.Write([]byte("pong"))
	require.Nil(t, err)
	connectConn.(*net.TCPConn).CloseWrite()
	resp, err = io.ReadAll(br)
	require.Nil(t, err)
	require.Equal(t, "echo:pong", string(resp))
}

func startEchoUntilEOF(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.Nil(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				data, _ := io.ReadAll(c)
				_, _ = c.Write([]byte("echo:" + string(data)))
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestH2TunnelLargePayload(t *testing.T) {
	payload := make([]byte, 8<<20)
	_, err := rand.Read(payload)
	require.Nil(t, err)
	sum := sha256.Sum256(payload)

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(w, r.Body)
	}))
	defer origin.Close()

	remoteAddr := newRealRemote(t, []string{"h2"})
	localAddr := newForceForwardLocal(t, remoteAddr)

	client := insecureClient(localAddr)
	client.Timeout = 30 * time.Second
	resp, err := client.Post(origin.URL, "application/octet-stream", bytes.NewReader(payload))
	require.Nil(t, err)
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	require.Nil(t, err)
	require.Equal(t, sum, sha256.Sum256(got))
}

func TestLocalToH1OnlyRemoteFails(t *testing.T) {
	remoteAddr := newRealRemote(t, []string{"http/1.1"})
	localAddr := newForceForwardLocal(t, remoteAddr)

	connectConn, err := net.Dial("tcp", localAddr)
	require.Nil(t, err)
	defer connectConn.Close()
	_, err = fmt.Fprintf(connectConn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	require.Nil(t, err)
	br := bufio.NewReader(connectConn)
	statusLine, err := br.ReadString('\n')
	require.Nil(t, err)
	require.Contains(t, statusLine, "502")

	conn, err := net.Dial("tcp", localAddr)
	require.Nil(t, err)
	defer conn.Close()
	rep := doSOCKS5Handshake(t, conn, 0x01, 0x03, domainAddr("example.com"), 443)
	require.Equal(t, byte(0x01), rep)
}

func TestRemoteRejectsH1WithValidAPIKey(t *testing.T) {
	srv := httptest.NewServer(newTestRemote(testRemoteSecret))
	defer srv.Close()

	req, err := http.NewRequest(http.MethodConnect, srv.URL, nil)
	require.Nil(t, err)
	req.Header.Set("X-Api-Key", testRemoteSecret)

	resp, err := http.DefaultClient.Do(req)
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestDecoyH1AndH2(t *testing.T) {
	decoy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("decoy-content"))
	}))
	defer decoy.Close()

	newRemote := func() *remoteProxyServer {
		return &remoteProxyServer{
			secretKey:              testRemoteSecret,
			staticReversedAddr:     decoy.URL,
			enableWebsiteRatelimit: false,
			fallbackHosts:          newFallbackHosts(time.Hour),
		}
	}

	h1srv := httptest.NewServer(newRemote())
	defer h1srv.Close()
	resp, err := http.Get(h1srv.URL + "/")
	require.Nil(t, err)
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.Nil(t, err)
	require.Equal(t, "decoy-content", string(body))

	resp, err = http.Get(h1srv.URL + "/robots.txt")
	require.Nil(t, err)
	body, err = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.Nil(t, err)
	require.Contains(t, string(body), "Disallow")

	h2srv := newRemoteServer(newRemote(), nil, []string{"h2", "http/1.1"})
	defer h2srv.Close()
	h2client := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: true,
	}}
	resp, err = h2client.Get(h2srv.URL + "/")
	require.Nil(t, err)
	require.Equal(t, "HTTP/2.0", resp.Proto)
	body, err = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.Nil(t, err)
	require.Equal(t, "decoy-content", string(body))
}

func TestPoolOverflowQueuesViaH2FlowControl(t *testing.T) {
	remote := newTestRemote(testRemoteSecret)
	srv := httptest.NewUnstartedServer(remote)
	srv.TLS = &tls.Config{NextProtos: []string{"h2"}}
	require.Nil(t, http2.ConfigureServer(srv.Config, &http2.Server{MaxConcurrentStreams: 1}))
	srv.StartTLS()
	defer srv.Close()
	remoteAddr := strings.TrimPrefix(srv.URL, "https://")

	tunnel := newTunnelClient(remoteAddr, "https", testRemoteSecret, 1, &tls.Config{InsecureSkipVerify: true})
	ctx := context.Background()

	echoAddr := startEchoUntilEOF(t)

	t1, err := tunnel.ConnectTunnel(ctx, echoAddr)
	require.Nil(t, err)
	defer t1.Close()
	t2, err := tunnel.ConnectTunnel(ctx, echoAddr)
	require.Nil(t, err)
	defer t2.Close()

	t3ch := make(chan *tunnelStream, 1)
	errch := make(chan error, 1)
	go func() {
		st, err := tunnel.ConnectTunnel(ctx, echoAddr)
		if err != nil {
			errch <- err
			return
		}
		t3ch <- st
	}()

	select {
	case st := <-t3ch:
		require.Nil(t, st.Close())
		t.Fatal("t3 established while all transport connections were full")
	case err := <-errch:
		t.Fatalf("t3 failed instead of queuing: %v", err)
	case <-time.After(500 * time.Millisecond):
	}

	require.Nil(t, t1.Close())
	select {
	case st := <-t3ch:
		require.Nil(t, st.Close())
	case err := <-errch:
		t.Fatalf("t3 failed waiting for a free stream slot: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("t3 did not establish after a stream slot freed up")
	}
}

func TestConnectTunnelNon200(t *testing.T) {
	remoteAddr, _ := mockH2RemoteProxy(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	tunnel := newTunnelClient(remoteAddr, "https", testRemoteSecret, 2, &tls.Config{InsecureSkipVerify: true})

	_, err := tunnel.ConnectTunnel(context.Background(), "example.com:443")
	require.Error(t, err)
	require.Contains(t, err.Error(), "403")
}

func TestPoolReusesTransportConnection(t *testing.T) {
	ln := newTrackingListener(t)
	srv := newRemoteServer(newTestRemote(testRemoteSecret), ln, []string{"h2"})
	defer srv.Close()
	remoteAddr := strings.TrimPrefix(srv.URL, "https://")
	localAddr := newForceForwardLocal(t, remoteAddr)

	echoAddr := startEchoUntilEOF(t)
	_, echoPort := splitHostPort(t, echoAddr)

	for range 2 {
		conn := doSOCKS5Connect(t, localAddr, 0x01, []byte{127, 0, 0, 1}, echoPort)
		require.Nil(t, conn.Close())
	}
	require.Len(t, ln.tracked(), 1)
}

func TestPoolEvictsDeadTransportConnection(t *testing.T) {
	ln := newTrackingListener(t)
	srv := newRemoteServer(newTestRemote(testRemoteSecret), ln, []string{"h2"})
	defer srv.Close()
	remoteAddr := strings.TrimPrefix(srv.URL, "https://")
	localAddr := newForceForwardLocal(t, remoteAddr)

	echoAddr := startEchoUntilEOF(t)
	_, echoPort := splitHostPort(t, echoAddr)

	conn := doSOCKS5Connect(t, localAddr, 0x01, []byte{127, 0, 0, 1}, echoPort)
	require.Nil(t, conn.Close())

	for _, c := range ln.tracked() {
		_ = c.Close()
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		c, err := net.Dial("tcp", localAddr)
		if err == nil {
			rep := doSOCKS5Handshake(t, c, 0x01, 0x01, []byte{127, 0, 0, 1}, echoPort)
			if rep == 0x00 {
				_ = c.Close()
				break
			}
		}
		if c != nil {
			_ = c.Close()
		}
		if time.Now().After(deadline) {
			t.Fatal("pool did not recover after transport connection death")
		}
		time.Sleep(50 * time.Millisecond)
	}

	require.GreaterOrEqual(t, len(ln.tracked()), 2)
}

func TestAPNICIPThroughTunnel(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("apnic-mirror"))
	}))
	defer origin.Close()

	remoteAddr := newRealRemote(t, []string{"h2"})

	_, originPort := splitHostPort(t, origin.Listener.Addr().String())
	tunnel := newTunnelClient(remoteAddr, "https", testRemoteSecret, 2, &tls.Config{InsecureSkipVerify: true})
	client := &http.Client{
		Transport: &http.Transport{
			DialContext:     tunnel.DialContext,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 10 * time.Second,
	}
	resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/apnic", originPort))
	require.Nil(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.Nil(t, err)
	require.Equal(t, "apnic-mirror", string(body))
}
