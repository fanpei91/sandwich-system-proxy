package main

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestChinaIPRangeContains(t *testing.T) {
	china := newChinaIPRangeDB()
	cn := "106.85.37.170"
	require.True(t, china.contains(net.ParseIP(cn)))

	cn = "2001:da8:1001:7::88"
	require.True(t, china.contains(net.ParseIP(cn)))

	usa := "172.217.11.68"
	require.False(t, china.contains(net.ParseIP(usa)))

	usa = "2001:470:4:1ee::2"
	require.False(t, china.contains(net.ParseIP(usa)))

	loopback := "127.0.0.1"
	require.False(t, china.contains(net.ParseIP(loopback)))

	loopback = "::1"
	require.False(t, china.contains(net.ParseIP(loopback)))

	private := "192.168.1.1"
	require.False(t, china.contains(net.ParseIP(private)))

	private = "fc00::"
	require.False(t, china.contains(net.ParseIP(private)))

	cn = "183.2.172.185"
	require.True(t, china.contains(net.ParseIP(cn)))
}

func BenchmarkIsChinaIP(b *testing.B) {
	china := newChinaIPRangeDB()
	usa := net.ParseIP("172.217.11.68")
	for i := 0; i < b.N; i++ {
		china.contains(usa)
	}
}
