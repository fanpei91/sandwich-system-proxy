//go:build darwin
// +build darwin

package main

import (
	"bufio"
	"net"
	"os"
	"strings"
)

func goLookupIPFiles(name string) (addrs []net.IPAddr) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return nil
	}

	f, err := os.Open("/etc/hosts")
	if err != nil {
		return nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		ip := net.ParseIP(fields[0])
		if ip == nil {
			continue
		}

		for _, host := range fields[1:] {
			if strings.EqualFold(strings.TrimSuffix(host, "."), name) {
				addrs = append(addrs, net.IPAddr{IP: ip})
				break
			}
		}
	}

	return addrs
}
