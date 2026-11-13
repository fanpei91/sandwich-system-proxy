package main

import (
	"bufio"
	"net"
)

// sniffingListener 嗅探入站连接的首字节：0x05 走 SOCKS5，其余走 HTTP 代理。
// 两种协议的处理器共用同一个端口，避免新增监听端口。
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

// peekConn 把嗅探阶段缓冲的字节重新喂回给读取方。
type peekConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *peekConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}
