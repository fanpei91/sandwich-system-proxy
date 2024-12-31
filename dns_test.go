package main

import (
    "log"
    "testing"
)

var (
    defaultTestDoHProvider = "https://doh.360.cn/dns-query"
)

func TestLookupStaticHost(t *testing.T) {
    log.Println(goLookupIPFiles("youtube.com"))
    log.Println(goLookupIPFiles("localhost"))
    log.Println(goLookupIPFiles("host.docker.internal"))
    log.Println((&dnsOverHostsFile{}).lookup("host.docker.internal"))
}

func TestCachedDNSLookUP(t *testing.T) {
    dns := newCachedDNS(&dnsOverHostsFile{}, &dnsOverHTTPS{provider: defaultTestDoHProvider}, &dnsOverUDP{})
    log.Println(dns.lookup("youtube.com"))
    log.Println(dns.lookup("localhost"))
    log.Println(dns.lookup("www.google.com"))
    log.Println(dns.lookup("www.baidu.com"))
}

func TestDNSOverHTTPSLookUP(t *testing.T) {
    dns := &dnsOverHTTPS{provider: defaultTestDoHProvider}
    log.Println(dns.lookup("www.baidu.com"))
}

func BenchmarkCachedDNSLookUP(b *testing.B) {
    var dns dnsResovler
    dns = newCachedDNS(
        &dnsOverHostsFile{},
        &dnsOverHTTPS{provider: defaultTestDoHProvider},
        &dnsOverUDP{},
    )

    for i := 0; i < b.N; i++ {
        dns.lookup("www.baidu.com")
    }
}

func BenchmarkUDPDNSLookUP(b *testing.B) {
    var dns dnsResovler
    dns = &dnsOverUDP{}

    for i := 0; i < b.N; i++ {
        dns.lookup("www.baidu.com")
    }
}
