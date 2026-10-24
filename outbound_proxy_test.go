package main

import (
	"bytes"
	"io"
	"net"
	"strconv"
	"syscall"
	"testing"
	"time"
)

type errReader struct {
	err error
}

func (r errReader) Read([]byte) (int, error) {
	return 0, r.err
}

func TestFallbackSet(t *testing.T) {
	set := newFallbackHosts(time.Hour)
	if set.contains("example.com:443") {
		t.Fatal("unexpected host in empty set")
	}

	set.add("example.com:443")
	if !set.contains("example.com:443") {
		t.Fatal("host not recorded")
	}
}

func TestFallbackSetExpires(t *testing.T) {
	set := newFallbackHosts(time.Millisecond)
	set.add("example.com:443")
	time.Sleep(5 * time.Millisecond)

	if set.contains("example.com:443") {
		t.Fatal("expected host to expire")
	}

	set.mu.RLock()
	_, ok := set.hosts["example.com:443"]
	set.mu.RUnlock()
	if ok {
		t.Fatal("expected expired host to be removed")
	}
}

func TestParseOutboundProxy(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		wantNil  bool
		wantAddr string
		wantUser string
		wantPass string
	}{
		{"empty", "", true, "", "", ""},
		{"address-only", "127.0.0.1:40000", false, "127.0.0.1:40000", "", ""},
		{"socks5-url", "socks5://127.0.0.1:40000", false, "127.0.0.1:40000", "", ""},
		{"socks5h-url", "socks5h://127.0.0.1:40000", false, "127.0.0.1:40000", "", ""},
		{"with-auth", "socks5://user:pass@127.0.0.1:40000", false, "127.0.0.1:40000", "user", "pass"},
	}

	for _, c := range cases {
		got, err := parseOutboundProxy(c.in)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", c.name, err)
		}
		if c.wantNil {
			if got != nil {
				t.Fatalf("%s: got %+v, want nil", c.name, got)
			}
			continue
		}
		if got == nil {
			t.Fatalf("%s: got nil", c.name)
		}
		if got.addr != c.wantAddr {
			t.Fatalf("%s: addr = %q, want %q", c.name, got.addr, c.wantAddr)
		}
		if c.wantUser == "" {
			if got.auth != nil {
				t.Fatalf("%s: unexpected auth %+v", c.name, got.auth)
			}
			continue
		}
		if got.auth == nil || got.auth.User != c.wantUser || got.auth.Password != c.wantPass {
			t.Fatalf("%s: auth = %+v, want %q/%q", c.name, got.auth, c.wantUser, c.wantPass)
		}
	}
}

func TestParseOutboundProxyMode(t *testing.T) {
	cases := []struct {
		in      string
		want    outboundProxyMode
		wantErr bool
	}{
		{"", outboundProxyModeFallback, false},
		{"fallback", outboundProxyModeFallback, false},
		{"always", outboundProxyModeAlways, false},
		{" always ", outboundProxyModeAlways, false},
		{"never", "", true},
	}

	for _, c := range cases {
		got, err := parseOutboundProxyMode(c.in)
		if c.wantErr {
			if err == nil {
				t.Fatalf("%q: expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%q: unexpected error: %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("%q: got %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseOutboundProxyInvalidScheme(t *testing.T) {
	if _, err := parseOutboundProxy("http://127.0.0.1:40000"); err == nil {
		t.Fatal("expected error for unsupported scheme")
	}
}

func TestResetTrackingReader(t *testing.T) {
	reader := &resetTrackingReader{r: errReader{err: syscall.ECONNRESET}}
	_, _ = reader.Read(make([]byte, 1))
	if !reader.reset {
		t.Fatal("expected reset to be tracked")
	}

	reader = &resetTrackingReader{r: errReader{err: io.EOF}}
	_, _ = reader.Read(make([]byte, 1))
	if reader.reset {
		t.Fatal("unexpected reset for non-reset error")
	}
}

func TestDialSOCKS5(t *testing.T) {
	addr, target := startSOCKS5Server(t, false)
	cfg, err := parseOutboundProxy(addr)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := dialSOCKS5(cfg, "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	assertSOCKS5Target(t, target)
	assertEcho(t, conn)
}

func TestDialSOCKS5WithAuth(t *testing.T) {
	addr, target := startSOCKS5Server(t, true)
	cfg, err := parseOutboundProxy("socks5://user:pass@" + addr)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := dialSOCKS5(cfg, "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	assertSOCKS5Target(t, target)
	assertEcho(t, conn)
}

func TestDialSOCKS5WithWrongAuth(t *testing.T) {
	addr, _ := startSOCKS5Server(t, true)
	cfg, err := parseOutboundProxy("socks5://user:wrong@" + addr)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := dialSOCKS5(cfg, "example.com:443")
	if err == nil {
		conn.Close()
		t.Fatal("expected authentication failure")
	}
}

func startSOCKS5Server(t *testing.T, requireAuth bool) (string, <-chan string) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	target := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if err := serveSOCKS5(conn, target, requireAuth); err != nil {
			return
		}
		_, _ = io.Copy(conn, conn)
	}()

	return ln.Addr().String(), target
}

func assertSOCKS5Target(t *testing.T, target <-chan string) {
	t.Helper()
	if got := <-target; got != "example.com:443" {
		t.Fatalf("got target %q, want %q", got, "example.com:443")
	}
}

func assertEcho(t *testing.T, conn net.Conn) {
	t.Helper()
	payload := []byte("ping")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("got %q, want %q", buf, payload)
	}
}

func serveSOCKS5(conn net.Conn, target chan<- string, requireAuth bool) error {
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		return err
	}
	if greeting[0] != 0x05 {
		return io.ErrUnexpectedEOF
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	if requireAuth {
		if !bytes.Contains(methods, []byte{0x02}) {
			return io.ErrUnexpectedEOF
		}
		if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
			return err
		}

		authHead := make([]byte, 2)
		if _, err := io.ReadFull(conn, authHead); err != nil {
			return err
		}
		if authHead[0] != 0x01 {
			return io.ErrUnexpectedEOF
		}
		user := make([]byte, int(authHead[1]))
		if _, err := io.ReadFull(conn, user); err != nil {
			return err
		}
		passLen := make([]byte, 1)
		if _, err := io.ReadFull(conn, passLen); err != nil {
			return err
		}
		pass := make([]byte, int(passLen[0]))
		if _, err := io.ReadFull(conn, pass); err != nil {
			return err
		}
		if string(user) != "user" || string(pass) != "pass" {
			_, _ = conn.Write([]byte{0x01, 0x01})
			return io.ErrUnexpectedEOF
		}
		if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
			return err
		}
	} else if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return err
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[0] != 0x05 || head[1] != 0x01 {
		return io.ErrUnexpectedEOF
	}

	var host string
	switch head[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return err
		}
		host = net.IP(b).String()
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(conn, b); err != nil {
			return err
		}
		host = string(b)
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return err
		}
		host = net.IP(b).String()
	default:
		return io.ErrUnexpectedEOF
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return err
	}
	port := int(portBuf[0])<<8 | int(portBuf[1])
	target <- net.JoinHostPort(host, strconv.Itoa(port))

	_, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0})
	return err
}
