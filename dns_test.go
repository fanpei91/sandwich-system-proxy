package main

import (
	"log"
	"testing"
)

func TestLookupStaticHost(t *testing.T) {
	log.Println(goLookupIPFiles("youtube.com"))
	log.Println(goLookupIPFiles("localhost"))
	log.Println(goLookupIPFiles("host.docker.internal"))
	log.Println((&dnsOverHostsFile{}).lookup("host.docker.internal"))
}

func TestCachedDNSLookUP(t *testing.T) {
	dns := newCachedDNS(&dnsOverHostsFile{}, &dnsOverHTTPS{provider: "https://doh.360.cn/resolve"}, &dnsOverUDP{})
	log.Println(dns.lookup("youtube.com"))
	log.Println(dns.lookup("localhost"))
	log.Println(dns.lookup("www.google.com"))
	log.Println(dns.lookup("www.baidu.com"))
}

func TestDNSOverHTTPSLookUP(t *testing.T) {
	dns := &dnsOverHTTPS{provider: "https://doh.360.cn/resolve"}
	log.Println(dns.lookup("www.baidu.com"))
}

func BenchmarkCachedDNSLookUP(b *testing.B) {
	var dns dns
	dns = newCachedDNS(
		&dnsOverHostsFile{},
		&dnsOverHTTPS{},
		&dnsOverUDP{},
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
