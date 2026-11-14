package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

const headerAPIKey = "X-Api-Key"

const (
	tunnelPoolOverflowFactor = 2
	tunnelDialTimeout        = 10 * time.Second
)

type tunnelClient struct {
	addr      string
	scheme    string
	secretKey string
	poolSize  int
	tlsConfig *tls.Config

	h2Transport *http2.Transport

	mu      sync.Mutex
	conns   []*http2.ClientConn
	dialing int
}

func newTunnelClient(addr, scheme, secretKey string, poolSize int, tlsConfig *tls.Config) *tunnelClient {
	if poolSize < 1 {
		poolSize = 1
	}
	return &tunnelClient{
		addr:        addr,
		scheme:      scheme,
		secretKey:   secretKey,
		poolSize:    poolSize,
		tlsConfig:   tlsConfig,
		h2Transport: &http2.Transport{DisableCompression: true, StrictMaxConcurrentStreams: true},
	}
}

func (c *tunnelClient) overflowCap() int {
	return tunnelPoolOverflowFactor * c.poolSize
}

func (c *tunnelClient) acquire(ctx context.Context) (*http2.ClientConn, error) {
	c.mu.Lock()
	c.evictDeadLocked()

	bestIdx, _ := c.leastUsableConnLocked(func(cc *http2.ClientConn) bool {
		st := cc.State()
		return st.MaxConcurrentStreams == 0 ||
			uint64(st.StreamsActive) < uint64(st.MaxConcurrentStreams)
	})
	if bestIdx != -1 {
		cc := c.conns[bestIdx]
		c.mu.Unlock()
		return cc, nil
	}

	if len(c.conns)+c.dialing < c.overflowCap() {
		c.dialing++
		c.mu.Unlock()

		cc, err := c.dial(ctx)

		c.mu.Lock()
		c.dialing--
		if err != nil {
			c.mu.Unlock()
			return nil, err
		}
		c.conns = append(c.conns, cc)
		c.mu.Unlock()
		return cc, nil
	}

	bestIdx, _ = c.leastUsableConnLocked(func(cc *http2.ClientConn) bool { return true })
	if bestIdx != -1 {
		cc := c.conns[bestIdx]
		c.mu.Unlock()
		return cc, nil
	}

	c.mu.Unlock()
	return nil, fmt.Errorf("all transport connections to %s are dead and pool is full (%d)", c.addr, c.overflowCap())
}

func (c *tunnelClient) leastUsableConnLocked(eligible func(*http2.ClientConn) bool) (int, int) {
	bestIdx, bestActive := -1, 0
	for i, cc := range c.conns {
		st := cc.State()
		if st.Closed || st.Closing {
			continue
		}
		if !eligible(cc) {
			continue
		}
		if bestIdx == -1 || st.StreamsActive < bestActive {
			bestIdx, bestActive = i, st.StreamsActive
		}
	}
	return bestIdx, bestActive
}

func (c *tunnelClient) evictDeadLocked() {
	alive := c.conns[:0]
	for _, cc := range c.conns {
		st := cc.State()
		if st.Closed || st.Closing {
			log.Printf("tunnel pool: evicted transport connection to %s (closed or GOAWAY with %d active streams)", c.addr, st.StreamsActive)
			if st.StreamsActive == 0 {
				_ = cc.Close()
			}
			continue
		}
		alive = append(alive, cc)
	}
	c.conns = alive
}

func (c *tunnelClient) dial(ctx context.Context) (*http2.ClientConn, error) {
	ctx, cancel := context.WithTimeout(ctx, tunnelDialTimeout)
	defer cancel()

	dialer := &net.Dialer{Timeout: tunnelDialTimeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, fmt.Errorf("dial remote proxy %s: %w", c.addr, err)
	}

	conn := net.Conn(rawConn)
	if c.scheme == "https" {
		host, _, splitErr := net.SplitHostPort(c.addr)
		if splitErr != nil {
			host = c.addr
		}
		cfg := &tls.Config{
			ServerName: host,
			NextProtos: []string{"h2"},
			MinVersion: tls.VersionTLS12,
		}
		if c.tlsConfig != nil {
			cfg = c.tlsConfig.Clone()
			cfg.NextProtos = []string{"h2"}
			if cfg.ServerName == "" {
				cfg.ServerName = host
			}
			if cfg.MinVersion == 0 {
				cfg.MinVersion = tls.VersionTLS12
			}
		}
		tlsConn := tls.Client(rawConn, cfg)
		_ = tlsConn.SetDeadline(time.Now().Add(tunnelDialTimeout))
		if err := tlsConn.Handshake(); err != nil {
			_ = rawConn.Close()
			return nil, fmt.Errorf("negotiate h2 with remote proxy %s: %w (local and remote must be upgraded together)", c.addr, err)
		}
		_ = tlsConn.SetDeadline(time.Time{})
		if proto := tlsConn.ConnectionState().NegotiatedProtocol; proto != "h2" {
			_ = rawConn.Close()
			return nil, fmt.Errorf("remote proxy %s negotiated ALPN %q, want \"h2\" (local and remote must be upgraded together)", c.addr, proto)
		}
		conn = tlsConn
	}

	cc, err := c.h2Transport.NewClientConn(conn)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("open h2 transport connection to %s: %w", c.addr, err)
	}
	return cc, nil
}

func (c *tunnelClient) evictIfConnLevelError(cc *http2.ClientConn, err error) {
	var connErr http2.ConnectionError
	st := cc.State()
	if !errors.As(err, &connErr) && !st.Closed && !st.Closing {
		return
	}
	c.mu.Lock()
	for i, existing := range c.conns {
		if existing == cc {
			log.Printf("tunnel pool: evicted transport connection to %s after error: %v", c.addr, err)
			c.conns = append(c.conns[:i], c.conns[i+1:]...)
			break
		}
	}
	c.mu.Unlock()
	if st.StreamsActive == 0 || st.Closed {
		_ = cc.Close()
	}
}

func (c *tunnelClient) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	cc, err := c.acquire(ctx)
	if err != nil {
		return nil, err
	}
	r := new(http.Request)
	*r = *req
	r.Header = make(http.Header, len(req.Header)+1)
	for k, vv := range req.Header {
		r.Header[k] = append([]string(nil), vv...)
	}
	r.Header.Set(headerAPIKey, c.secretKey)
	resp, err := cc.RoundTrip(r)
	if err != nil {
		c.evictIfConnLevelError(cc, err)
		return nil, err
	}
	return resp, nil
}

func (c *tunnelClient) ConnectTunnel(ctx context.Context, target string) (*tunnelStream, error) {
	pr, pw := io.Pipe()

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Scheme: "https", Host: target},
		Host:   target,
		Header: make(http.Header),
		Body:   pr,
	}
	req.Header.Set(headerAPIKey, c.secretKey)
	req.ContentLength = -1
	req = req.WithContext(context.Background())

	cc, err := c.acquire(ctx)
	if err != nil {
		_ = pw.CloseWithError(err)
		return nil, err
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		_ = pw.CloseWithError(err)
		c.evictIfConnLevelError(cc, err)
		return nil, fmt.Errorf("open h2 tunnel via remote proxy %s for CONNECT %s: %w", c.addr, target, err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
		_ = pw.Close()
		return nil, fmt.Errorf("remote proxy %s refused CONNECT to %s: %s (%s)", c.addr, target, resp.Status, strings.TrimSpace(string(body)))
	}
	return &tunnelStream{resp: resp, pipeW: pw}, nil
}

func (c *tunnelClient) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("unsupported network %q", network)
	}
	stream, err := c.ConnectTunnel(ctx, addr)
	if err != nil {
		return nil, err
	}
	zeroAddr := &net.TCPAddr{}
	return &tunnelNetConn{
		tunnelStream: stream,
		localAddr:    zeroAddr,
		remoteAddr:   zeroAddr,
	}, nil
}

type tunnelStream struct {
	resp  *http.Response
	pipeW *io.PipeWriter
}

func (s *tunnelStream) Read(p []byte) (int, error)  { return s.resp.Body.Read(p) }
func (s *tunnelStream) Write(p []byte) (int, error) { return s.pipeW.Write(p) }

func (s *tunnelStream) Close() error {
	_ = s.CloseWrite()
	_ = s.CloseRead()
	return nil
}

func (s *tunnelStream) CloseWrite() error { return s.pipeW.Close() }
func (s *tunnelStream) CloseRead() error  { return s.resp.Body.Close() }

type tunnelNetConn struct {
	*tunnelStream
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c *tunnelNetConn) LocalAddr() net.Addr                { return c.localAddr }
func (c *tunnelNetConn) RemoteAddr() net.Addr               { return c.remoteAddr }
func (c *tunnelNetConn) SetDeadline(t time.Time) error      { return nil }
func (c *tunnelNetConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *tunnelNetConn) SetWriteDeadline(t time.Time) error { return nil }

type flushWriter struct {
	w io.Writer
	f http.Flusher
}

func (fw *flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	fw.f.Flush()
	return n, err
}

func isHopByHopHeader(h string) bool {
	switch http.CanonicalHeaderKey(h) {
	case "Connection", "Proxy-Connection", "Keep-Alive",
		"Proxy-Authenticate", "Proxy-Authorization",
		"Te", "Trailer", "Transfer-Encoding", "Upgrade":
		return true
	}
	return false
}

func filterHopByHop(h http.Header) http.Header {
	var connTokens []string
	for _, v := range h["Connection"] {
		for f := range strings.SplitSeq(v, ",") {
			if t := strings.TrimSpace(f); t != "" {
				connTokens = append(connTokens, strings.ToLower(t))
			}
		}
	}
	out := make(http.Header, len(h))
	for k, vv := range h {
		if isHopByHopHeader(k) {
			continue
		}
		skip := false
		lower := strings.ToLower(http.CanonicalHeaderKey(k))
		if slices.Contains(connTokens, lower) {
			skip = true
		}
		if skip {
			continue
		}
		out[http.CanonicalHeaderKey(k)] = append([]string(nil), vv...)
	}
	return out
}
