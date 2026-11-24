package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
)

// tcpRemoteTransport speaks the original local <-> remote protocol: a single
// HTTP proxy request over TCP (optionally TLS) whose response - including the
// 200 reply to CONNECT - is relayed to the client verbatim. That is why it
// must not write anything to the client itself.
type tcpRemoteTransport struct {
	remoteProxyAddr *url.URL
	secretKey       string
	// tlsConfig is nil in production, which lets crypto/tls infer the SNI from
	// the dial address, exactly like the previous tls.Dial call.
	tlsConfig *tls.Config
}

func (t *tcpRemoteTransport) name() string { return transportHTTPS }

func (t *tcpRemoteTransport) close() error { return nil }

func (t *tcpRemoteTransport) dial(ctx context.Context, _ net.Conn, req *http.Request, _ string) (io.ReadWriteCloser, error) {
	addr := appendPort(t.remoteProxyAddr.Host, t.remoteProxyAddr.Scheme)

	var conn net.Conn
	var err error
	if t.remoteProxyAddr.Scheme == "https" {
		d := &tls.Dialer{Config: t.tlsConfig}
		conn, err = d.DialContext(ctx, "tcp", addr)
	} else {
		var d net.Dialer
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errTransportUnavailable, err)
	}

	req.Header.Set(headerSecret, t.secretKey)
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}
