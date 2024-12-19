//go:build darwin
// +build darwin

package main

import "net"
import _ "unsafe"

//go:linkname goLookupIPFiles net.goLookupIPFiles
func goLookupIPFiles(name string) (addrs []net.IPAddr)
