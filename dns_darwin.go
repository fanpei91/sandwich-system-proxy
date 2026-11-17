//go:build darwin
// +build darwin

package main

import (
	"bufio"
	"net"
	"os"
	"strings"
)

const hostsFilePath = "/etc/hosts"

func goLookupIPFiles(name string) (addrs []net.IPAddr) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return nil
	}

	f, err := os.Open(hostsFilePath)
	if err != nil {
		return nil
	}
	defer f.Close()

	target := strings.ToLower(name)
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = line[:idx]
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
			if strings.ToLower(host) != target {
				continue
			}
			key := ip.String()
			if seen[key] {
				break
			}
			seen[key] = true
			addrs = append(addrs, net.IPAddr{IP: ip})
			break
		}
	}

	return addrs
}
