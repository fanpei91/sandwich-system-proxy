//go:build !darwin
// +build !darwin

package main

import "net"

func goLookupIPFiles(name string) (addrs []net.IPAddr) {
	return nil
}
