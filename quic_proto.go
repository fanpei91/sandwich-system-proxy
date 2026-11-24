package main

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	// quicProtoName is the ALPN protocol of the local <-> remote tunnel.
	// It shares the UDP port with HTTP/3, which keeps the remote looking like
	// an ordinary HTTP/3 website to anything that probes it.
	quicProtoName = "sandwich/1"

	// quicProtoVersion is the framing version of the tunnel preamble.
	quicProtoVersion byte = 1

	// Guards against a hostile peer claiming absurd lengths.
	maxPreambleSecretLen = 4 << 10
	maxPreambleTargetLen = 1 << 10

	// tunnelFlagConnect marks a CONNECT request, i.e. the local proxy has
	// already answered the client's CONNECT on its own.
	tunnelFlagConnect byte = 1 << 0

	tunnelAckOK              byte = 0
	tunnelAckDialFailed      byte = 1
	tunnelAckAuthFailed      byte = 2
	tunnelAckUnsupportedPeer byte = 3
)

var errMalformedPreamble = errors.New("malformed tunnel preamble")

// tunnelPreamble is the header of every tunnel stream, written by the local
// proxy and answered by the remote proxy with a single ack byte. Everything
// after the ack is opaque bytes in both directions.
type tunnelPreamble struct {
	version    byte
	flags      byte
	secret     string
	targetAddr string
}

func (p *tunnelPreamble) isConnect() bool {
	return p.flags&tunnelFlagConnect != 0
}

func writeTunnelPreamble(w io.Writer, p *tunnelPreamble) error {
	if len(p.secret) > maxPreambleSecretLen || len(p.targetAddr) > maxPreambleTargetLen {
		return errMalformedPreamble
	}

	buf := make([]byte, 0, 6+len(p.secret)+len(p.targetAddr))
	buf = append(buf, p.version, p.flags)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(p.secret)))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(p.targetAddr)))
	buf = append(buf, p.secret...)
	buf = append(buf, p.targetAddr...)

	_, err := w.Write(buf)
	return err
}

func readTunnelPreamble(r io.Reader) (*tunnelPreamble, error) {
	header := make([]byte, 6)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	secretLen := int(binary.BigEndian.Uint16(header[2:4]))
	targetLen := int(binary.BigEndian.Uint16(header[4:6]))
	if secretLen > maxPreambleSecretLen || targetLen > maxPreambleTargetLen {
		return nil, errMalformedPreamble
	}

	body := make([]byte, secretLen+targetLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}

	p := &tunnelPreamble{
		version:    header[0],
		flags:      header[1],
		secret:     string(body[:secretLen]),
		targetAddr: string(body[secretLen:]),
	}
	if p.targetAddr == "" {
		return nil, errMalformedPreamble
	}
	return p, nil
}

func writeTunnelAck(w io.Writer, code byte) error {
	_, err := w.Write([]byte{code})
	return err
}

func readTunnelAck(r io.Reader) (byte, error) {
	var buf [1]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	return buf[0], nil
}
