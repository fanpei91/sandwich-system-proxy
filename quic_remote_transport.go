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
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	// quicHandshakeTimeout bounds the QUIC handshake so a silently dropped UDP
	// path degrades to TCP quickly instead of hanging the client.
	quicHandshakeTimeout  = 2 * time.Second
	quicStreamOpenTimeout = 5 * time.Second
	quicPreambleTimeout   = 5 * time.Second

	quicFirstBackoff = 30 * time.Second
	quicMaxBackoff   = 5 * time.Minute
)

func quicTunnelConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout:           quicHandshakeTimeout,
		MaxIdleTimeout:                 45 * time.Second,
		KeepAlivePeriod:                15 * time.Second,
		MaxIncomingStreams:             512,
		InitialStreamReceiveWindow:     1 << 20,
		MaxStreamReceiveWindow:         1 << 20,
		InitialConnectionReceiveWindow: 8 << 20,
		MaxConnectionReceiveWindow:     8 << 20,
		// 0-RTT is deliberately disabled: replayed request bodies are not worth
		// the one round trip it saves.
		Allow0RTT: false,
	}
}

// quicRemoteTransport multiplexes every tunnel over one long lived QUIC
// connection. Transport level failures mark QUIC as degraded for a growing
// backoff window, during which dial returns errTransportUnavailable right away
// so the caller can use TCP without paying the handshake timeout again.
type quicRemoteTransport struct {
	addr             string
	secretKey        string
	handshakeTimeout time.Duration
	tlsConfig        *tls.Config
	quicConfig       *quic.Config

	transport *quic.Transport
	udpConn   *net.UDPConn

	dialMu sync.Mutex // serializes redials

	mu            sync.Mutex
	conn          *quic.Conn
	degradedUntil time.Time
	backoff       time.Duration
	degraded      bool
}

func newQUICRemoteTransport(remoteProxyAddr *url.URL, secretKey string) (*quicRemoteTransport, error) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		return nil, fmt.Errorf("listen udp for quic: %w", err)
	}

	t := &quicRemoteTransport{
		addr:             appendPort(remoteProxyAddr.Host, remoteProxyAddr.Scheme),
		secretKey:        secretKey,
		handshakeTimeout: quicHandshakeTimeout,
		tlsConfig: &tls.Config{
			ServerName: remoteProxyAddr.Hostname(),
			NextProtos: []string{quicProtoName},
			MinVersion: tls.VersionTLS13,
		},
		quicConfig: quicTunnelConfig(),
		transport:  &quic.Transport{Conn: udpConn},
		udpConn:    udpConn,
	}
	return t, nil
}

func (t *quicRemoteTransport) name() string { return transportQUIC }

func (t *quicRemoteTransport) close() error {
	t.mu.Lock()
	conn := t.conn
	t.conn = nil
	t.mu.Unlock()

	if conn != nil {
		conn.CloseWithError(0, "")
	}
	_ = t.transport.Close()
	return t.udpConn.Close()
}

func (t *quicRemoteTransport) dial(ctx context.Context, client net.Conn, req *http.Request, targetAddr string) (io.ReadWriteCloser, error) {
	stream, conn, err := t.openStream(ctx, req, targetAddr)
	if err != nil {
		return nil, err
	}

	if req.Method == http.MethodConnect {
		reply := fmt.Sprintf("%s 200 Connection established\r\n\r\n", req.Proto)
		if _, err := client.Write([]byte(reply)); err != nil {
			stream.CancelRead(quic.StreamErrorCode(0))
			stream.CancelWrite(quic.StreamErrorCode(0))
			return nil, err
		}
		return stream, nil
	}

	// Non-CONNECT requests travel as normalized origin-form bytes, exactly like
	// the TCP transport hands them to the remote proxy's HTTP server.
	if err := req.Write(stream); err != nil {
		t.streamFailed(conn, err)
		return nil, err
	}
	return stream, nil
}

func (t *quicRemoteTransport) openStream(ctx context.Context, req *http.Request, targetAddr string) (*quic.Stream, *quic.Conn, error) {
	if wait := t.degradedFor(); wait > 0 {
		return nil, nil, fmt.Errorf("%w: quic degraded for another %s", errTransportUnavailable, wait.Round(time.Second))
	}

	conn, err := t.connection(ctx)
	if err != nil {
		t.markFailure(err)
		return nil, nil, fmt.Errorf("%w: %v", errTransportUnavailable, err)
	}

	openCtx, cancel := context.WithTimeout(ctx, quicStreamOpenTimeout)
	defer cancel()
	stream, err := conn.OpenStreamSync(openCtx)
	if err != nil {
		// A busy connection that cannot grant a stream is not a broken
		// connection, so let this request fall back without degrading QUIC.
		t.streamFailed(conn, err)
		return nil, nil, fmt.Errorf("%w: %v", errTransportUnavailable, err)
	}

	flags := byte(0)
	if req.Method == http.MethodConnect {
		flags |= tunnelFlagConnect
	}
	preamble := &tunnelPreamble{
		version:    quicProtoVersion,
		flags:      flags,
		secret:     t.secretKey,
		targetAddr: targetAddr,
	}

	stream.SetWriteDeadline(time.Now().Add(quicPreambleTimeout))
	if err := writeTunnelPreamble(stream, preamble); err != nil {
		t.streamFailed(conn, err)
		return nil, nil, fmt.Errorf("%w: %v", errTransportUnavailable, err)
	}

	stream.SetReadDeadline(time.Now().Add(quicPreambleTimeout))
	ack, err := readTunnelAck(stream)
	stream.SetReadDeadline(time.Time{})
	stream.SetWriteDeadline(time.Time{})
	if err != nil {
		t.streamFailed(conn, err)
		return nil, nil, fmt.Errorf("%w: %v", errTransportUnavailable, err)
	}

	switch ack {
	case tunnelAckOK:
		t.markHealthy()
		return stream, conn, nil
	case tunnelAckDialFailed:
		stream.Close()
		return nil, nil, errRemoteDialFailed
	case tunnelAckAuthFailed:
		stream.Close()
		return nil, nil, errRemoteAuthFailed
	default:
		stream.Close()
		return nil, nil, errRemoteUnsupported
	}
}

func (t *quicRemoteTransport) connection(ctx context.Context) (*quic.Conn, error) {
	t.mu.Lock()
	if conn := t.conn; conn != nil && conn.Context().Err() == nil {
		t.mu.Unlock()
		return conn, nil
	}
	t.mu.Unlock()

	t.dialMu.Lock()
	defer t.dialMu.Unlock()

	t.mu.Lock()
	if conn := t.conn; conn != nil && conn.Context().Err() == nil {
		t.mu.Unlock()
		return conn, nil
	}
	t.mu.Unlock()

	udpAddr, err := net.ResolveUDPAddr("udp", t.addr)
	if err != nil {
		return nil, err
	}

	handshakeCtx, cancel := context.WithTimeout(ctx, t.handshakeTimeout)
	defer cancel()
	conn, err := t.transport.Dial(handshakeCtx, udpAddr, t.tlsConfig, t.quicConfig)
	if err != nil {
		return nil, err
	}

	t.mu.Lock()
	t.conn = conn
	t.mu.Unlock()
	return conn, nil
}

func (t *quicRemoteTransport) degradedFor() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	return time.Until(t.degradedUntil)
}

// streamFailed only degrades when the shared connection itself is gone, so a
// single broken stream cannot reset every other tunnel.
func (t *quicRemoteTransport) streamFailed(conn *quic.Conn, err error) {
	if conn.Context().Err() != nil {
		t.markFailure(err)
	}
}

// markFailure records a transport level failure and closes the connection so
// the next attempt starts from a clean handshake.
func (t *quicRemoteTransport) markFailure(err error) {
	if errors.Is(err, context.Canceled) {
		// The client went away, that says nothing about the QUIC path.
		return
	}

	t.mu.Lock()
	conn := t.conn
	t.conn = nil

	if t.backoff == 0 {
		t.backoff = quicFirstBackoff
	} else if t.backoff *= 2; t.backoff > quicMaxBackoff {
		t.backoff = quicMaxBackoff
	}
	t.degradedUntil = time.Now().Add(t.backoff)

	first := !t.degraded
	t.degraded = true
	t.mu.Unlock()

	if conn != nil {
		conn.CloseWithError(0, "")
	}
	if first {
		log.Printf("[quic] remote proxy %s unavailable: %v; falling back to %s for %s",
			t.addr, err, transportHTTPS, t.backoff)
	}
}

func (t *quicRemoteTransport) markHealthy() {
	t.mu.Lock()
	wasDegraded := t.degraded
	t.degraded = false
	t.backoff = 0
	t.degradedUntil = time.Time{}
	t.mu.Unlock()

	if wasDegraded {
		log.Printf("[quic] remote proxy %s recovered", t.addr)
	}
}
