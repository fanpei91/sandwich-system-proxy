package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"syscall"
)

const (
	socks5Version                    = 0x05
	socks5NoAuthMethod               = 0x00
	socks5NoAcceptableMethod         = 0xFF
	socks5CmdConnect                 = 0x01
	socks5AtypeIPv4                  = 0x01
	socks5AtypeDomain                = 0x03
	socks5AtypeIPv6                  = 0x04
	socks5RepSuccess                 = 0x00
	socks5RepGeneralFailure          = 0x01
	socks5RepHostUnreachable         = 0x04
	socks5RepConnectionRefused       = 0x05
	socks5RepCommandNotSupported     = 0x07
	socks5RepAddressTypeNotSupported = 0x08
)

var errSOCKS5AddressTypeNotSupported = errors.New("unsupported address type")

type socks5Request struct {
	cmd  byte
	host string
	port string
}

func (proxy *localProxyServer) serveSOCKS5(br *bufio.Reader, conn net.Conn) {
	defer conn.Close()

	if err := socks5Greet(br, conn); err != nil {
		log.Printf("socks5 greeting error: %v", err)
		return
	}

	req, err := readSOCKS5Request(br)
	if err != nil {
		if errors.Is(err, errSOCKS5AddressTypeNotSupported) {
			writeSOCKS5Reply(conn, socks5RepAddressTypeNotSupported)
		}
		log.Printf("socks5 request error: %v", err)
		return
	}
	if req.cmd != socks5CmdConnect {
		writeSOCKS5Reply(conn, socks5RepCommandNotSupported)
		return
	}

	target := net.JoinHostPort(req.host, req.port)

	targetIP, err := proxy.resolveTargetIP(req.host)
	if err != nil {
		log.Printf("resolve %s error: %v", req.host, err)
		writeSOCKS5Reply(conn, socks5RepHostUnreachable)
		return
	}

	if !proxy.useRemoteProxy(targetIP) {
		dialAddr := net.JoinHostPort(targetIP.String(), req.port)
		log.Println(fmt.Sprintf("origin <-> local(socks5) <-> %s(%s)", target, targetIP))
		targetConn, err := net.Dial("tcp", dialAddr)
		if err != nil {
			log.Printf("dial %s error: %v", dialAddr, err)
			writeSOCKS5Reply(conn, socks5DialErrorReply(err))
			return
		}
		defer targetConn.Close()
		if err := writeSOCKS5Reply(conn, socks5RepSuccess); err != nil {
			return
		}
		go transfer(conn, targetConn)
		transfer(targetConn, &hijackedClientConn{Reader: br, conn: conn})
		return
	}

	log.Println(fmt.Sprintf("origin <-> local(socks5) <-> remote <-> %s(%s)", target, targetIP))
	proxy.forwardSOCKS5ToRemoteProxy(br, conn, target)
}

func socks5Greet(br *bufio.Reader, conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(br, header); err != nil {
		return err
	}
	if header[0] != socks5Version {
		return fmt.Errorf("unsupported version 0x%02x", header[0])
	}
	if header[1] == 0 {
		return errors.New("no methods offered")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return err
	}
	if !bytes.Contains(methods, []byte{socks5NoAuthMethod}) {
		_, err := conn.Write([]byte{socks5Version, socks5NoAcceptableMethod})
		if err != nil {
			return err
		}
		return errors.New("client does not offer no-authentication method")
	}
	_, err := conn.Write([]byte{socks5Version, socks5NoAuthMethod})
	return err
}

func readSOCKS5Request(br *bufio.Reader) (*socks5Request, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(br, header); err != nil {
		return nil, err
	}
	version, cmd, atyp := header[0], header[1], header[3]
	if version != socks5Version {
		return nil, fmt.Errorf("unsupported version 0x%02x", version)
	}

	var host string
	switch atyp {
	case socks5AtypeIPv4:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(br, ip); err != nil {
			return nil, err
		}
		host = net.IP(ip).String()
	case socks5AtypeIPv6:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(br, ip); err != nil {
			return nil, err
		}
		host = net.IP(ip).String()
	case socks5AtypeDomain:
		length, err := br.ReadByte()
		if err != nil {
			return nil, err
		}
		if length == 0 {
			return nil, errors.New("empty domain")
		}
		domain := make([]byte, int(length))
		if _, err := io.ReadFull(br, domain); err != nil {
			return nil, err
		}
		host = string(domain)
	default:
		return nil, errSOCKS5AddressTypeNotSupported
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(br, portBytes); err != nil {
		return nil, err
	}
	port := strconv.Itoa(int(uint16(portBytes[0])<<8 | uint16(portBytes[1])))

	return &socks5Request{cmd: cmd, host: host, port: port}, nil
}

func writeSOCKS5Reply(conn net.Conn, rep byte) error {
	// VER REP RSV ATYP(IPv4) 0.0.0.0 : 0.0.0.0, BND.* 回 0.0.0.0:0
	buf := []byte{socks5Version, rep, 0x00, socks5AtypeIPv4, 0, 0, 0, 0, 0, 0}
	_, err := conn.Write(buf)
	return err
}

func socks5DialErrorReply(err error) byte {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return socks5RepConnectionRefused
	}
	return socks5RepGeneralFailure
}

func (proxy *localProxyServer) forwardSOCKS5ToRemoteProxy(clientBR *bufio.Reader, client net.Conn, target string) {
	remoteProxyAddr := appendPort(proxy.remoteProxyAddr.Host, proxy.remoteProxyAddr.Scheme)

	var remoteProxy net.Conn
	var err error
	if proxy.remoteProxyAddr.Scheme == "https" {
		remoteProxy, err = tls.Dial("tcp", remoteProxyAddr, nil)
	} else {
		remoteProxy, err = net.Dial("tcp", remoteProxyAddr)
	}
	if err != nil {
		log.Printf("dial remote proxy %s error: %v", remoteProxyAddr, err)
		writeSOCKS5Reply(client, socks5DialErrorReply(err))
		return
	}
	defer remoteProxy.Close()

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s: %s\r\n\r\n", target, target, headerSecret, proxy.secretKey)
	if _, err := io.WriteString(remoteProxy, req); err != nil {
		log.Printf("write remote proxy %s error: %v", remoteProxyAddr, err)
		writeSOCKS5Reply(client, socks5RepGeneralFailure)
		return
	}

	remoteReader := bufio.NewReader(remoteProxy)
	statusLine, err := remoteReader.ReadString('\n')
	if err != nil {
		log.Printf("read remote proxy %s response error: %v", remoteProxyAddr, err)
		writeSOCKS5Reply(client, socks5RepGeneralFailure)
		return
	}

	statusCode, err := parseSOCKS5UpstreamStatus(statusLine)
	if err != nil || statusCode != 200 {
		drainSOCKS5UpstreamHeaders(remoteReader)
		log.Printf("remote proxy %s connect %s response: %s", remoteProxyAddr, target, strings.TrimSpace(statusLine))
		writeSOCKS5Reply(client, socks5RepGeneralFailure)
		return
	}
	if err := drainSOCKS5UpstreamHeaders(remoteReader); err != nil {
		log.Printf("read remote proxy %s response headers error: %v", remoteProxyAddr, err)
		writeSOCKS5Reply(client, socks5RepGeneralFailure)
		return
	}

	if err := writeSOCKS5Reply(client, socks5RepSuccess); err != nil {
		return
	}

	go transfer(client, &hijackedClientConn{Reader: remoteReader, conn: remoteProxy})
	transfer(remoteProxy, &hijackedClientConn{Reader: clientBR, conn: client})
}

func parseSOCKS5UpstreamStatus(statusLine string) (int, error) {
	fields := strings.Fields(statusLine)
	if len(fields) < 2 {
		return 0, fmt.Errorf("malformed status line %q", strings.TrimSpace(statusLine))
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, fmt.Errorf("malformed status code in %q", strings.TrimSpace(statusLine))
	}
	return code, nil
}

func drainSOCKS5UpstreamHeaders(br *bufio.Reader) error {
	for i := 0; ; i++ {
		if i >= 100 {
			return errors.New("too many header lines")
		}
		line, err := br.ReadString('\n')
		if err != nil {
			return err
		}
		if len(line) > 8192 {
			return errors.New("header line too long")
		}
		if line == "\r\n" || line == "\n" {
			return nil
		}
	}
}
