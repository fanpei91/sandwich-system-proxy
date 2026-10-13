package main

import (
	"bytes"
	"net"
	"testing"
	"time"
)

type fakeConn struct {
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
	writes   [][]byte
}

func newFakeConn(read []byte) *fakeConn {
	return &fakeConn{
		readBuf:  bytes.NewBuffer(read),
		writeBuf: &bytes.Buffer{},
	}
}

func (c *fakeConn) Read(p []byte) (int, error)  { return c.readBuf.Read(p) }
func (c *fakeConn) Close() error                { return nil }
func (c *fakeConn) LocalAddr() net.Addr         { return nil }
func (c *fakeConn) RemoteAddr() net.Addr        { return nil }
func (c *fakeConn) SetDeadline(time.Time) error { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

func (c *fakeConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), p...))
	return c.writeBuf.Write(p)
}

func buildClientHello(bodyLen int) []byte {
	record := make([]byte, 5+bodyLen)
	record[0] = tlsHandshakeRecordType
	record[1] = 0x03
	record[2] = 0x01
	record[3] = byte(bodyLen >> 8)
	record[4] = byte(bodyLen)
	for i := 5; i < len(record); i++ {
		record[i] = byte(i)
	}
	return record
}

func TestFragmentOffsets(t *testing.T) {
	cases := []struct {
		name     string
		total    int
		count    int
		firstLen int
		want     []int
	}{
		{"two-fragments", 100, 2, 5, []int{5, 100}},
		{"three-fragments", 100, 3, 5, []int{5, 53, 100}},
		{"first-larger-than-total", 3, 2, 10, []int{3}},
		{"count-larger-than-total", 5, 10, 1, []int{1, 2, 3, 4, 5}},
		{"clamp-count-to-two", 100, 1, 5, []int{5, 100}},
	}

	for _, c := range cases {
		got := fragmentOffsets(c.total, c.count, c.firstLen)
		if len(got) != len(c.want) {
			t.Fatalf("%s: got %v, want %v", c.name, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("%s: got %v, want %v", c.name, got, c.want)
			}
		}
	}
}

func TestCopyClientToTargetFragmentsClientHello(t *testing.T) {
	record := buildClientHello(200)
	trailing := []byte("application-data")

	src := newFakeConn(append(append([]byte(nil), record...), trailing...))
	dst := newFakeConn(nil)

	copyClientToTarget(dst, src, fragmentOptions{
		enabled:          true,
		count:            2,
		firstFragmentLen: 5,
		delay:            time.Millisecond,
	})

	if !bytes.Equal(dst.writeBuf.Bytes(), append(append([]byte(nil), record...), trailing...)) {
		t.Fatal("forwarded bytes do not match the source")
	}
	if len(dst.writes) != 3 {
		t.Fatalf("expected 3 writes, got %d", len(dst.writes))
	}
	if len(dst.writes[0]) != 5 {
		t.Fatalf("expected first fragment of 5 bytes, got %d", len(dst.writes[0]))
	}
}

func TestCopyClientToTargetPassesThroughNonTLS(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	src := newFakeConn(payload)
	dst := newFakeConn(nil)

	copyClientToTarget(dst, src, fragmentOptions{enabled: true, count: 2, firstFragmentLen: 5})

	if !bytes.Equal(dst.writeBuf.Bytes(), payload) {
		t.Fatal("non-TLS payload should be forwarded verbatim")
	}
	if len(dst.writes) > 2 {
		t.Fatalf("non-TLS payload should not be fragmented, got %d writes", len(dst.writes))
	}
}

func TestCopyClientToTargetDisabled(t *testing.T) {
	record := buildClientHello(200)
	src := newFakeConn(record)
	dst := newFakeConn(nil)

	copyClientToTarget(dst, src, fragmentOptions{enabled: false})

	if !bytes.Equal(dst.writeBuf.Bytes(), record) {
		t.Fatal("disabled fragmentation should forward verbatim")
	}
	if len(dst.writes) != 1 {
		t.Fatalf("expected a single write when disabled, got %d", len(dst.writes))
	}
}

func TestCopyClientToTargetShortBody(t *testing.T) {
	payload := []byte{0x16, 0x03}
	src := newFakeConn(payload)
	dst := newFakeConn(nil)

	copyClientToTarget(dst, src, fragmentOptions{enabled: true, count: 2, firstFragmentLen: 5})

	if !bytes.Equal(dst.writeBuf.Bytes(), payload) {
		t.Fatalf("got %v, want %v", dst.writeBuf.Bytes(), payload)
	}
}
