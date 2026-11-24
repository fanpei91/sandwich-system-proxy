package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const quicTargetDialTimeout = 10 * time.Second

// quicRemoteProxyServer serves two ALPNs on one UDP port: HTTP/3 for anyone who
// probes the domain with a browser or a scanner (it gets the same masquerade
// site as TCP visitors), and the tunnel protocol for local proxies.
type quicRemoteProxyServer struct {
	secretKey string
	transport *quic.Transport
	udpConn   *net.UDPConn
	listener  *quic.Listener
	http3     *http3.Server
}

func newQUICRemoteProxyServer(listenAddr, secretKey string, website http.Handler, tlsConfig *tls.Config) (*quicRemoteProxyServer, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	quicTLSConfig := tlsConfig.Clone()
	quicTLSConfig.NextProtos = []string{http3.NextProtoH3, quicProtoName}

	transport := &quic.Transport{Conn: udpConn}
	listener, err := transport.Listen(quicTLSConfig, quicTunnelConfig())
	if err != nil {
		udpConn.Close()
		transport.Close()
		return nil, err
	}

	return &quicRemoteProxyServer{
		secretKey: secretKey,
		transport: transport,
		udpConn:   udpConn,
		listener:  listener,
		http3:     &http3.Server{Handler: website},
	}, nil
}

func (s *quicRemoteProxyServer) Addr() net.Addr { return s.listener.Addr() }

func (s *quicRemoteProxyServer) Serve() error {
	for {
		conn, err := s.listener.Accept(context.Background())
		if err != nil {
			if errors.Is(err, quic.ErrServerClosed) {
				return nil
			}
			return err
		}
		go s.handleConn(conn)
	}
}

func (s *quicRemoteProxyServer) Close() error {
	s.http3.Close()
	s.listener.Close()
	_ = s.transport.Close()
	return s.udpConn.Close()
}

func (s *quicRemoteProxyServer) handleConn(conn *quic.Conn) {
	switch conn.ConnectionState().TLS.NegotiatedProtocol {
	case quicProtoName:
		s.handleTunnelConn(conn)
	case http3.NextProtoH3:
		// Browsers and scanners probing the port get the same website as TCP
		// visitors; their errors are not worth logging.
		_ = s.http3.ServeQUICConn(conn)
	default:
		// Unknown ALPN: close without any application level detail, so the
		// port reveals as little as possible.
		conn.CloseWithError(0, "")
	}
}

func (s *quicRemoteProxyServer) handleTunnelConn(conn *quic.Conn) {
	for {
		stream, err := conn.AcceptStream(conn.Context())
		if err != nil {
			return
		}
		go s.handleTunnelStream(stream)
	}
}

func (s *quicRemoteProxyServer) handleTunnelStream(stream *quic.Stream) {
	stream.SetReadDeadline(time.Now().Add(quicPreambleTimeout))
	preamble, err := readTunnelPreamble(stream)
	if err != nil {
		stream.CancelRead(quic.StreamErrorCode(0))
		stream.CancelWrite(quic.StreamErrorCode(0))
		return
	}

	if preamble.version != quicProtoVersion {
		writeTunnelAck(stream, tunnelAckUnsupportedPeer)
		stream.Close()
		return
	}

	if subtle.ConstantTimeCompare([]byte(preamble.secret), []byte(s.secretKey)) != 1 {
		writeTunnelAck(stream, tunnelAckAuthFailed)
		stream.Close()
		return
	}

	stream.SetReadDeadline(time.Time{})

	target, err := net.DialTimeout("tcp", preamble.targetAddr, quicTargetDialTimeout)
	if err != nil {
		log.Printf("[quic] dial %s error: %v", preamble.targetAddr, err)
		writeTunnelAck(stream, tunnelAckDialFailed)
		stream.Close()
		return
	}

	if err := writeTunnelAck(stream, tunnelAckOK); err != nil {
		target.Close()
		stream.Close()
		return
	}

	go func() {
		defer target.Close()
		defer stream.CancelRead(quic.StreamErrorCode(0))
		transferQuietly(target, stream)
	}()

	defer target.Close()
	defer stream.Close()
	transferQuietly(stream, target)
}

func transferQuietly(dst io.Writer, src io.Reader) {
	_, _ = io.Copy(dst, src)
}
