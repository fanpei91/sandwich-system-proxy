package main

import (
	"bufio"
	"net"
)

type sniffingListener struct {
	net.Listener
	handleSOCKS5 func(*bufio.Reader, net.Conn)
}

func (l *sniffingListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		br := bufio.NewReader(conn)
		first, err := br.Peek(1)
		if err != nil {
			conn.Close()
			continue
		}
		if first[0] == socks5Version {
			go l.handleSOCKS5(br, conn)
			continue
		}
		return &peekConn{Conn: conn, reader: br}, nil
	}
}

type peekConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *peekConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}
