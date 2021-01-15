package main

import (
	"log"
	"net/http"
	"testing"
)
import _ "unsafe"

func TestLookupStaticHost(t *testing.T) {
	log.Println(goLookupIPFiles("youtube.com"))
	log.Println(goLookupIPFiles("localhost"))
	log.Println(goLookupIPFiles("host.docker.internal"))
	log.Println((&dnsOverHostsFile{}).lookup("host.docker.internal"))
}

func TestSmartDNSLookUP(t *testing.T) {
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: nil,
		},
	}
	dns := newSmartDNS((&dnsOverHostsFile{}).lookup, (&dnsOverHTTPS{client: client}).lookup, (&dnsOverUDP{}).lookup)
	log.Println(dns.lookup("youtube.com"))
	log.Println(dns.lookup("localhost"))
	log.Println(dns.lookup("www.google.com"))
}

func BenchmarkSmartDNSLookUP(b *testing.B) {
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: nil,
		},
	}
	var dns dns
	dns = newSmartDNS(
		(&dnsOverHostsFile{}).lookup,
		(&dnsOverHTTPS{client: client}).lookup,
		(&dnsOverUDP{}).lookup,
	)

	for i := 0; i < b.N; i++ {
		dns.lookup("www.baidu.com")
	}
}

func BenchmarkUDPDNSLookUP(b *testing.B) {
	var dns dns
	dns = &dnsOverUDP{}

	for i := 0; i < b.N; i++ {
		dns.lookup("www.baidu.com")
	}
}
