package main

import (
    "context"
    "encoding/base64"
    "fmt"
    "github.com/miekg/dns"
    "io"
    "log"
    "net"
    "net/http"
    "net/url"
    "sync"
    "time"

    _ "unsafe"

    "github.com/golang/groupcache/lru"
)

const (
    timeout = 10 * time.Second
)

type answerCache struct {
    ip        net.IP
    expiredAt time.Time
}

type dnsResolver struct {
    waiters  []chan answerCache
    answer   answerCache
    finished bool
}

type dnsResovler interface {
    lookup(host string) (err error, ip net.IP, expriedAt time.Time)
    name() string
}

type dnsOverHostsFile struct{}

func (d *dnsOverHostsFile) lookup(host string) (err error, ip net.IP, expriedAt time.Time) {
    res := goLookupIPFiles(host)
    if len(res) == 0 {
        return nil, nil, time.Now()
    }
    return nil, res[0].IP, time.Now()
}
func (d *dnsOverHostsFile) name() string {
    return "dnsOverHostsFile"
}

type dnsOverUDP struct{}

func (d *dnsOverUDP) lookup(host string) (err error, ip net.IP, expriedAt time.Time) {
    expriedAt = time.Now()

    answers, err := net.LookupIP(host)
    if err != nil {
        err = fmt.Errorf("lookup error: %v", err)
        return err, nil, expriedAt
    }

    return nil, answers[0], expriedAt
}

func (d *dnsOverUDP) name() string {
    return "dnsOverUDP"
}

type dnsOverHTTPS struct {
    staticTTL time.Duration
    provider  string
}

func (d *dnsOverHTTPS) lookup(host string) (err error, ip net.IP, expriedAt time.Time) {
    expriedAt = time.Now()

    msg := new(dns.Msg)
    msg.SetQuestion(dns.Fqdn(host), dns.TypeA)
    msg.RecursionDesired = true

    buf, err := msg.Pack()
    if err != nil {
        return fmt.Errorf("pack dns message error: %v", err), nil, expriedAt
    }

    queryURL, err := url.Parse(d.provider)
    if err != nil {
        return fmt.Errorf("parse provider error: %v", err), nil, expriedAt
    }

    dnsParam := base64.RawURLEncoding.EncodeToString(buf)
    query := queryURL.Query()
    query.Set("dns", dnsParam)
    queryURL.RawQuery = query.Encode()

    req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, queryURL.String(), nil)
    if err != nil {
        return fmt.Errorf("create request error: %v", err), nil, expriedAt
    }

    req.Header.Set("Accept", "application/dns-message")
    req.Header.Set("Content-Type", "application/dns-message")

    client := &http.Client{
        Transport: &http.Transport{
            Proxy: nil,
        },
    }
    resp, err := client.Do(req)
    if err != nil {
        return fmt.Errorf("do request error: %v", err), nil, expriedAt
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("unexpected status code: %d", resp.StatusCode), nil, expriedAt
    }

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return fmt.Errorf("read response error: %v", err), nil, expriedAt
    }

    response := new(dns.Msg)
    if err := response.Unpack(body); err != nil {
        return fmt.Errorf("unpack response error: %v", err), nil, expriedAt
    }

    for _, answer := range response.Answer {
        if a, ok := answer.(*dns.A); ok {
            ip = a.A
            expriedAt = time.Now().Add(time.Duration(a.Header().Ttl) * time.Second)
            return nil, ip, expriedAt
        }
    }

    return fmt.Errorf("no answer found"), nil, expriedAt
}

func (d *dnsOverHTTPS) name() string {
    return "dnsOverHTTPS"
}

type cachedDNS struct {
    sync.RWMutex
    backends []dnsResovler
    cache    *lru.Cache
}

func newCachedDNS(backends ...dnsResovler) *cachedDNS {
    d := &cachedDNS{
        cache: lru.New(2 << 15),
    }
    d.backends = append(d.backends, backends...)
    return d
}

func (d *cachedDNS) lookup(host string) (err error, ip net.IP, expriedAt time.Time) {
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
        return nil, resolver.answer.ip, resolver.answer.expiredAt
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
        return nil, answer.ip, answer.expiredAt
    case <-timeout.C:
        return fmt.Errorf("timeout"), nil, time.Now()
    }
}

func (d *cachedDNS) name() string {
    return "cachedDNS"
}

func (d *cachedDNS) do(host string) {
    var ip net.IP
    var expriedAt = time.Now()
    var err error

    for _, backend := range d.backends {
        if err, ip, expriedAt = backend.lookup(host); err != nil {
            log.Printf("backend(%s) lookup %s error: %v", backend.name(), host, err)
            continue
        }
        if ip == nil {
            continue
        }
        break
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
