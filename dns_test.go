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

func TestSmartDNSLookUP(t *testing.T) {
	dns := newSmartDNS((&dnsOverHostsFile{}).lookup, (&dnsOverHTTPS{provider: "https://doh.360.cn/resolve"}).lookup, (&dnsOverUDP{}).lookup)
	log.Println(dns.lookup("youtube.com"))
	log.Println(dns.lookup("localhost"))
	log.Println(dns.lookup("www.google.com"))
	log.Println(dns.lookup("www.baidu.com"))
}

func TestDNSOverHTTPSLookUP(t *testing.T) {
	dns := &dnsOverHTTPS{provider: "https://doh.360.cn/resolve"}
	log.Println(dns.lookup("www.baidu.com"))
}

func BenchmarkSmartDNSLookUP(b *testing.B) {
	var dns dns
	dns = newSmartDNS(
		(&dnsOverHostsFile{}).lookup,
		(&dnsOverHTTPS{}).lookup,
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
