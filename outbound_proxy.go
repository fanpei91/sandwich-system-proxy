package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/proxy"
)

type fallbackHosts struct {
	mu    sync.RWMutex
	hosts map[string]struct{}
}

func newFallbackHosts() *fallbackHosts {
	return &fallbackHosts{hosts: make(map[string]struct{})}
}

func (f *fallbackHosts) add(addr string) {
	f.mu.Lock()
	f.hosts[addr] = struct{}{}
	f.mu.Unlock()
}

func (f *fallbackHosts) contains(addr string) bool {
	f.mu.RLock()
	_, ok := f.hosts[addr]
	f.mu.RUnlock()
	return ok
}

type resetTrackingReader struct {
	r     io.Reader
	reset bool
}

func (r *resetTrackingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if errors.Is(err, syscall.ECONNRESET) {
		r.reset = true
	}
	return n, err
}

type socks5ProxyConfig struct {
	addr string
	auth *proxy.Auth
}

func parseOutboundProxy(raw string) (*socks5ProxyConfig, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if !strings.Contains(raw, "://") {
		raw = "socks5://" + raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "socks5" && u.Scheme != "socks5h" {
		return nil, fmt.Errorf("unsupported outbound proxy scheme %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("missing outbound proxy address")
	}

	cfg := &socks5ProxyConfig{addr: u.Host}
	if u.User != nil {
		password, _ := u.User.Password()
		cfg.auth = &proxy.Auth{
			User:     u.User.Username(),
			Password: password,
		}
	}
	return cfg, nil
}

func dialSOCKS5(cfg *socks5ProxyConfig, targetAddr string) (net.Conn, error) {
	dialer, err := proxy.SOCKS5("tcp", cfg.addr, cfg.auth, proxy.Direct)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if cd, ok := dialer.(proxy.ContextDialer); ok {
		return cd.DialContext(ctx, "tcp", targetAddr)
	}
	return dialer.Dial("tcp", targetAddr)
}
