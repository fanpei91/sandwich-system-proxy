package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

const (
	headerSecret = "Misha-Secret"
)

const (
	typeIPv4 = 1
	typeIPv6 = 28
)

type localProxy struct {
	remoteProxyAddr   *url.URL
	secretKey         string
	chinaIPRangeDB    *IPRangeDB
	autoCrossFirewall bool
	client            *http.Client
	dns               dns
}

func (l *localProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	targetAddr := appendPort(req.Host, req.URL.Scheme)
	host, port, _ := net.SplitHostPort(targetAddr)

	if !l.autoCrossFirewall {
		l.remote(rw, req)
		return
	}

	targetIP := net.ParseIP(host)
	if targetIP == nil {
		targetIP, _ = l.dns.lookup(host)
	}
	if targetIP == nil {
		http.Error(rw, fmt.Sprintf("lookup %s: no such host", host), http.StatusServiceUnavailable)
		return
	}

	req.URL.Host = targetIP.String() + ":" + port
	if l.chinaIPRangeDB.contains(targetIP) || privateIPRange.contains(targetIP) {
		l.direct(rw, req, targetAddr)
		return
	}

	l.remote(rw, req)
}

func (l *localProxy) direct(rw http.ResponseWriter, req *http.Request, targetAddr string) {
	client, _, _ := rw.(http.Hijacker).Hijack()
	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusServiceUnavailable)
		return
	}

	if req.Method == http.MethodConnect {
		client.Write([]byte(fmt.Sprintf("%s 200 OK\r\n\r\n", req.Proto)))
	} else {
		if v := req.Header.Get("Proxy-Connection"); v != "" {
			req.Header.Del("Proxy-Connection")
			req.Header.Set("Connection", v)
		}
		req.Write(target)
	}

	go transfer(client, target)
	transfer(target, client)
}

func (l *localProxy) remote(rw http.ResponseWriter, req *http.Request) {
	client, _, _ := rw.(http.Hijacker).Hijack()
	var remoteProxy net.Conn
	var err error

	remoteProxyAddr := appendPort(l.remoteProxyAddr.Host, l.remoteProxyAddr.Scheme)

	if l.remoteProxyAddr.Scheme == "https" {
		remoteProxy, err = tls.Dial("tcp", remoteProxyAddr, nil)
	} else {
		remoteProxy, err = net.Dial("tcp", remoteProxyAddr)
	}
	if err != nil {
		return
	}

	req.Header.Set(headerSecret, l.secretKey)
	req.Write(remoteProxy)

	go transfer(remoteProxy, client)
	transfer(client, remoteProxy)
}

func (l *localProxy) pullLatestIPRange(ctx context.Context) error {
	addr := "http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, addr, nil)
	res, err := l.client.Do(req)
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return err
	}

	reader := bufio.NewReader(res.Body)
	var line []byte
	var db []*ipRange
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		if line, _, err = reader.ReadLine(); err != nil && err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		if len(line) == 0 || line[0] == '#' {
			continue
		}

		parts := strings.SplitN(string(line), "|", 6)
		if len(parts) != 6 {
			continue
		}

		cc, typ, start, value := parts[1], parts[2], parts[3], parts[4]
		if !(cc == "CN" && (typ == "ipv4" || typ == "ipv6")) {
			continue
		}

		prefixLength, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		if typ == "ipv4" {
			prefixLength = 32 - int(math.Log(float64(prefixLength))/math.Log(2))
		}

		db = append(db, &ipRange{value: fmt.Sprintf("%s/%d", start, prefixLength)})
	}

	if len(db) == 0 {
		return errors.New("empty ip range db")
	}

	l.chinaIPRangeDB.Lock()
	defer l.chinaIPRangeDB.Unlock()
	l.chinaIPRangeDB.db = db
	l.chinaIPRangeDB.init()
	sort.Sort(l.chinaIPRangeDB)
	return nil
}

func appendPort(host string, schema string) string {
	if strings.Index(host, ":") < 0 || strings.HasSuffix(host, "]") {
		if schema == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	return host
}
