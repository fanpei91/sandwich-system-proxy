package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testSecretKey = "test-secret"

func TestTunnelPreambleRoundTrip(t *testing.T) {
	p := &tunnelPreamble{
		version:    quicProtoVersion,
		flags:      tunnelFlagConnect,
		secret:     testSecretKey,
		targetAddr: "example.com:443",
	}

	var buf bytes.Buffer
	require.NoError(t, writeTunnelPreamble(&buf, p))

	got, err := readTunnelPreamble(&buf)
	require.NoError(t, err)
	require.Equal(t, p, got)
	require.True(t, got.isConnect())

	require.ErrorIs(t, writeTunnelPreamble(io.Discard, &tunnelPreamble{
		version:    quicProtoVersion,
		targetAddr: "example.com:443",
		secret:     string(make([]byte, maxPreambleSecretLen+1)),
	}), errMalformedPreamble)
}

func TestParseRemoteTransport(t *testing.T) {
	for _, mode := range []string{transportAuto, transportQUIC, transportHTTPS} {
		got, err := parseRemoteTransport(mode)
		require.NoError(t, err)
		require.Equal(t, mode, got)
	}
	_, err := parseRemoteTransport("tcp")
	require.Error(t, err)
}

// TestQUICTunnel runs the whole chain (client -> local -> QUIC -> remote ->
// target) for CONNECT and for plain HTTP requests.
func TestQUICTunnel(t *testing.T) {
	cert, roots := newTestCertificate(t)
	tcpURL, quicAddr := startTestRemoteProxy(t, cert)

	target := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(rw, "hello over connect %s", req.URL.Path)
	}))
	defer target.Close()

	plainTarget := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(rw, "hello over plain %s", req.URL.Path)
	}))
	defer plainTarget.Close()

	for name, transports := range map[string][]remoteTransport{
		"quic": {newTestQUICTransport(t, quicAddr, testSecretKey, roots)},
		"tcp":  {newTestTCPTransport(tcpURL, testSecretKey, roots)},
	} {
		t.Run(name, func(t *testing.T) {
			localURL := startTestLocalProxy(t, transports...)
			client := newTestProxyClient(localURL, true)
			defer client.CloseIdleConnections()

			res, err := client.Get(target.URL + "/connect")
			require.NoError(t, err)
			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			require.NoError(t, err)
			require.Equal(t, "hello over connect /connect", string(body))

			res, err = client.Get(plainTarget.URL + "/plain")
			require.NoError(t, err)
			body, err = io.ReadAll(res.Body)
			res.Body.Close()
			require.NoError(t, err)
			require.Equal(t, "hello over plain /plain", string(body))
		})
	}
}

// TestFallbackToTCP covers the deployment case where UDP is blocked: the very
// first request degrades to the HTTPS transport and still succeeds.
func TestFallbackToTCP(t *testing.T) {
	cert, roots := newTestCertificate(t)
	tcpURL, _ := startTestRemoteProxy(t, cert)

	target := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		fmt.Fprint(rw, "served over tcp")
	}))
	defer target.Close()

	deadQUIC := newTestQUICTransport(t, "127.0.0.1:1", testSecretKey, roots)
	deadQUIC.handshakeTimeout = 300 * time.Millisecond

	localURL := startTestLocalProxy(t, deadQUIC, newTestTCPTransport(tcpURL, testSecretKey, roots))
	client := newTestProxyClient(localURL, false)
	defer client.CloseIdleConnections()

	for i := 0; i < 2; i++ {
		res, err := client.Get(target.URL)
		require.NoError(t, err)
		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		require.NoError(t, err)
		require.Equal(t, "served over tcp", string(body))
	}

	require.True(t, deadQUIC.degraded, "quic should be marked degraded after a transport failure")
	require.Greater(t, deadQUIC.backoff, time.Duration(0))
}

func TestRemoteProxyFailuresDoNotDegradeQUIC(t *testing.T) {
	cert, roots := newTestCertificate(t)
	_, quicAddr := startTestRemoteProxy(t, cert)

	t.Run("wrong secret", func(t *testing.T) {
		qt := newTestQUICTransport(t, quicAddr, "wrong-secret", roots)
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		_, err := qt.dial(context.Background(), nil, req, "example.com:80")
		require.ErrorIs(t, err, errRemoteAuthFailed)
		require.False(t, qt.degraded)
	})

	t.Run("unreachable target", func(t *testing.T) {
		closed := httptest.NewServer(http.NotFoundHandler())
		closed.Close()

		qt := newTestQUICTransport(t, quicAddr, testSecretKey, roots)
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		_, err := qt.dial(context.Background(), nil, req, closed.Listener.Addr().String())
		require.ErrorIs(t, err, errRemoteDialFailed)
		require.False(t, qt.degraded)
	})
}

func TestQUICTransportRequiresTLSRemoteProxy(t *testing.T) {
	u, err := url.Parse("http://127.0.0.1:8080")
	require.NoError(t, err)

	_, err = newRemoteTransportSelector(u, testSecretKey, transportQUIC)
	require.Error(t, err)

	selector, err := newRemoteTransportSelector(u, testSecretKey, transportAuto)
	require.NoError(t, err)
	require.Len(t, selector.transports, 1, "plain http remote proxies only speak the tcp protocol")
}

func newTestCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sandwich-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	roots := x509.NewCertPool()
	roots.AddCert(leaf)

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, roots
}

// startTestRemoteProxy starts both faces of the remote proxy (TLS/TCP and
// QUIC/UDP) with the same secret and masquerade website.
func startTestRemoteProxy(t *testing.T, cert tls.Certificate) (*url.URL, string) {
	t.Helper()

	handler := &remoteProxyServer{
		secretKey:          testSecretKey,
		staticReversedAddr: "http://127.0.0.1:1",
	}

	tcpServer := httptest.NewUnstartedServer(handler)
	tcpServer.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	tcpServer.StartTLS()
	t.Cleanup(tcpServer.Close)

	tcpURL, err := url.Parse(tcpServer.URL)
	require.NoError(t, err)

	quicServer, err := newQUICRemoteProxyServer("127.0.0.1:0", testSecretKey, &tls.Config{Certificates: []tls.Certificate{cert}})
	require.NoError(t, err)
	t.Cleanup(func() { quicServer.Close() })
	go func() { _ = quicServer.Serve() }()

	return tcpURL, quicServer.Addr().String()
}

func startTestLocalProxy(t *testing.T, transports ...remoteTransport) *url.URL {
	t.Helper()

	local := &localProxyServer{
		transport:                 &remoteTransportSelector{transports: transports},
		secretKey:                 testSecretKey,
		forceForwardToRemoteProxy: true,
		client:                    http.DefaultClient,
	}

	server := httptest.NewServer(local)
	t.Cleanup(server.Close)

	localURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	return localURL
}

func newTestQUICTransport(t *testing.T, addr, secretKey string, roots *x509.CertPool) *quicRemoteTransport {
	t.Helper()

	remoteProxyURL, err := url.Parse("https://" + addr)
	require.NoError(t, err)

	transport, err := newQUICRemoteTransport(remoteProxyURL, secretKey)
	require.NoError(t, err)
	transport.tlsConfig.RootCAs = roots
	t.Cleanup(func() { transport.close() })

	return transport
}

func newTestTCPTransport(remoteProxyURL *url.URL, secretKey string, roots *x509.CertPool) *tcpRemoteTransport {
	return &tcpRemoteTransport{
		remoteProxyAddr: remoteProxyURL,
		secretKey:       secretKey,
		tlsConfig:       &tls.Config{RootCAs: roots},
	}
}

func newTestProxyClient(localURL *url.URL, insecureTarget bool) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(localURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureTarget},
		},
	}
}
