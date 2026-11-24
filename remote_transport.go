package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
)

const (
	transportAuto  = "auto"
	transportQUIC  = "quic"
	transportHTTPS = "https"
)

// errTransportUnavailable marks a failure of the transport itself, e.g. an
// unreachable remote proxy. Only these failures are worth retrying over another
// transport; configuration mistakes (wrong secret) and target failures are not.
var errTransportUnavailable = errors.New("remote proxy transport unavailable")

// remoteTransport opens a tunnel to the remote proxy for one hijacked client
// connection. Implementations own their protocol handshake and return a duplex
// byte stream once the remote proxy has connected to the target, so callers
// only have to pump bytes.
type remoteTransport interface {
	// dial returns a stream connected to targetAddr. When req is CONNECT the
	// implementation is responsible for answering the client with a 200 reply
	// before returning (the remote proxy of the TCP transport does that, the
	// QUIC transport writes it itself). If dial fails before anything was
	// written to client, the caller may still fall back to another transport.
	dial(ctx context.Context, client net.Conn, req *http.Request, targetAddr string) (io.ReadWriteCloser, error)
	name() string
	close() error
}

type remoteTransportSelector struct {
	transports []remoteTransport
}

func newRemoteTransportSelector(remoteProxyAddr *url.URL, secretKey string) (*remoteTransportSelector, error) {
	tcp := &tcpRemoteTransport{remoteProxyAddr: remoteProxyAddr, secretKey: secretKey}
	return &remoteTransportSelector{transports: []remoteTransport{tcp}}, nil
}

// dial tries every transport in order and reports which one was used. It only
// falls through to the next transport when the previous one was unavailable,
// never when the remote proxy answered with an application level failure.
func (s *remoteTransportSelector) dial(ctx context.Context, client net.Conn, req *http.Request, targetAddr string) (io.ReadWriteCloser, string, error) {
	if len(s.transports) == 0 {
		return nil, "", errors.New("no remote proxy transport configured")
	}

	var lastErr error
	for _, t := range s.transports {
		tunnel, err := t.dial(ctx, client, req, targetAddr)
		if err == nil {
			return tunnel, t.name(), nil
		}
		lastErr = err
		if !errors.Is(err, errTransportUnavailable) {
			return nil, t.name(), err
		}
	}
	return nil, s.transports[len(s.transports)-1].name(), lastErr
}

func (s *remoteTransportSelector) close() error {
	var firstErr error
	for _, t := range s.transports {
		if err := t.close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
