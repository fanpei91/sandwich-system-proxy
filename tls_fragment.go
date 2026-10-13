package main

import (
	"io"
	"net"
	"time"
)

const tlsHandshakeRecordType = 0x16

const maxTLSRecordLen = 1 << 14

type fragmentOptions struct {
	enabled          bool
	count            int
	firstFragmentLen int
	delay            time.Duration
}

func copyClientToTarget(dst net.Conn, src net.Conn, frag fragmentOptions) {
	defer dst.Close()
	defer src.Close()

	if tcp, ok := dst.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}

	if !frag.enabled {
		_, _ = io.Copy(dst, src)
		return
	}

	header := make([]byte, 5)
	n, err := io.ReadFull(src, header)
	if err != nil {
		if n > 0 {
			_, _ = dst.Write(header[:n])
		}
		return
	}

	if !isTLSHandshakeRecord(header) {
		if _, err = dst.Write(header); err != nil {
			return
		}
		_, _ = io.Copy(dst, src)
		return
	}

	recordLen := int(header[3])<<8 | int(header[4])
	if recordLen == 0 || recordLen > maxTLSRecordLen {
		if _, err = dst.Write(header); err != nil {
			return
		}
		_, _ = io.Copy(dst, src)
		return
	}

	record := make([]byte, 5+recordLen)
	copy(record, header)
	bodyRead, err := io.ReadFull(src, record[5:])
	if err != nil {
		if _, werr := dst.Write(record[:5+bodyRead]); werr != nil {
			return
		}
		return
	}

	if err = writeFragmented(dst, record, frag); err != nil {
		return
	}

	_, _ = io.Copy(dst, src)
}

func isTLSHandshakeRecord(header []byte) bool {
	return len(header) >= 5 && header[0] == tlsHandshakeRecordType && header[1] == 0x03
}

func writeFragmented(dst io.Writer, data []byte, frag fragmentOptions) error {
	offsets := fragmentOffsets(len(data), frag.count, frag.firstFragmentLen)

	start := 0
	for i, end := range offsets {
		if end <= start {
			continue
		}
		if _, err := dst.Write(data[start:end]); err != nil {
			return err
		}
		start = end
		if i != len(offsets)-1 && frag.delay > 0 {
			time.Sleep(frag.delay)
		}
	}
	return nil
}

func fragmentOffsets(total, count, firstLen int) []int {
	if total <= 0 {
		return nil
	}
	if firstLen < 1 {
		firstLen = 1
	}
	if firstLen >= total {
		return []int{total}
	}
	if count < 2 {
		count = 2
	}
	if count > total {
		count = total
	}

	offsets := make([]int, 0, count)
	offsets = append(offsets, firstLen)

	remaining := total - firstLen
	segments := count - 1
	base := remaining / segments
	extra := remaining % segments

	cur := firstLen
	for i := 0; i < segments; i++ {
		step := base
		if i < extra {
			step++
		}
		cur += step
		offsets = append(offsets, cur)
	}
	return offsets
}
