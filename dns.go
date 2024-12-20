package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	_ "unsafe"

	"github.com/golang/groupcache/lru"
)

const (
	timeout = 10 * time.Second
)

type answer struct {
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
	ip   net.IP
}

type response struct {
	Status int      `json:"Status"`
	Answer []answer `json:"Answer"`
}

type answerCache struct {
	ip        net.IP
	expiredAt time.Time
}

type dnsResolver struct {
	waiters  []chan answerCache
	answer   answerCache
	finished bool
}

type dns interface {
	lookup(host string) (ip net.IP, expriedAt time.Time)
}

type dnsOverHostsFile struct{}

func (d *dnsOverHostsFile) lookup(host string) (ip net.IP, expriedAt time.Time) {
	res := goLookupIPFiles(host)
	if len(res) == 0 {
		return nil, time.Now()
	}
	return res[0].IP, time.Now()
}

type dnsOverUDP struct{}

func (d *dnsOverUDP) lookup(host string) (ip net.IP, expriedAt time.Time) {
	expriedAt = time.Now()

	answers, err := net.LookupIP(host)
	if err != nil {
		return nil, expriedAt
	}

	return answers[0], expriedAt
}

type dnsOverHTTPS struct {
	staticTTL time.Duration
	provider  string
}

func (d *dnsOverHTTPS) lookup(host string) (ip net.IP, expriedAt time.Time) {
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: nil,
		},
	}

	provider := fmt.Sprintf("%s?name=%s", d.provider, host)
	req, _ := http.NewRequest(http.MethodGet, provider, nil)
	req.Header.Set("Accept", "application/dns-json")

	res, err := client.Do(req)
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil || res == nil {
		return nil, time.Now()
	}

	buf, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, time.Now()
	}

	rr := &response{}
	json.NewDecoder(bytes.NewBuffer(buf)).Decode(rr)
	if rr.Status != 0 {
		return nil, time.Now()
	}
	if len(rr.Answer) == 0 {
		return nil, time.Now()
	}

	var answer *answer
	for _, a := range rr.Answer {
		if a.Type == typeIPv4 || a.Type == typeIPv6 {
			answer = &a
			break
		}
	}

	if answer != nil {
		ip = net.ParseIP(answer.Data)
		expriedAt = time.Now().Add(time.Duration(answer.TTL) * time.Second)
		if d.staticTTL != 0 {
			expriedAt = time.Now().Add(d.staticTTL)
		}
	}

	return ip, expriedAt
}

type cachedDNS struct {
	sync.RWMutex
	backends []dns
	cache    *lru.Cache
}

func newCachedDNS(backends ...dns) *cachedDNS {
	d := &cachedDNS{
		cache: lru.New(2 << 15),
	}
	d.backends = append(d.backends, backends...)
	return d
}

func (d *cachedDNS) lookup(host string) (ip net.IP, expriedAt time.Time) {
	d.Lock()

	cached, ok := d.cache.Get(host)
	var resolver *dnsResolver
	if !ok {
		resolver = &dnsResolver{}
		d.cache.Add(host, resolver)
	} else {
		resolver = cached.(*dnsResolver)
		if resolver.finished && resolver.answer.expiredAt.Before(time.Now()) {
			resolver.finished = false
			ok = false
		}
	}

	if resolver.finished {
		d.Unlock()
		return resolver.answer.ip, resolver.answer.expiredAt
	}

	ch := make(chan answerCache, 1)
	resolver.waiters = append(resolver.waiters, ch)
	d.Unlock()

	if !ok {
		go d.do(host)
	}

	timeout := time.NewTimer(timeout)
	defer timeout.Stop()

	select {
	case answer := <-ch:
		return answer.ip, answer.expiredAt
	case <-timeout.C:
		return nil, time.Now()
	}
}

func (d *cachedDNS) do(host string) {
	var ip net.IP
	var expriedAt = time.Now()

	for _, backend := range d.backends {
		ip, expriedAt = backend.lookup(host)
		if ip != nil {
			break
		}
	}

	d.Lock()
	defer d.Unlock()

	cache, _ := d.cache.Get(host)
	resolver := cache.(*dnsResolver)
	resolver.finished = true
	resolver.answer.ip = ip
	resolver.answer.expiredAt = expriedAt

	for _, ch := range resolver.waiters {
		ch <- resolver.answer
		close(ch)
	}
	resolver.waiters = nil
}
