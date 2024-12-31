package main

import (
    "bufio"
    "context"
    "crypto/tls"
    "errors"
    "fmt"
    "io"
    "log"
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

type localProxyServer struct {
    remoteProxyAddr           *url.URL
    secretKey                 string
    chinaIPRangeDB            *iPRangeDB
    forceForwardToRemoteProxy bool
    client                    *http.Client
    dns                       dnsResovler
}

func (proxy *localProxyServer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
    targetAddr := appendPort(req.Host, req.URL.Scheme)
    host, port, _ := net.SplitHostPort(targetAddr)

    if proxy.forceForwardToRemoteProxy {
        proxy.forwardToRemoteProxy(rw, req)
        return
    }

    var err error
    targetIP := net.ParseIP(host)
    if targetIP == nil {
        if err, targetIP, _ = proxy.dns.lookup(host); err != nil {
            log.Printf("resolve %s error: %v", host, err)
        }
    }
    if targetIP == nil {
        http.Error(rw, fmt.Sprintf("lookup %s: no such host", host), http.StatusServiceUnavailable)
        return
    }

    req.URL.Host = targetIP.String() + ":" + port
    if proxy.chinaIPRangeDB.contains(targetIP) || privateIPRange.contains(targetIP) {
        log.Println(fmt.Sprintf("origin <-> local <-> %s(%s)", host, targetIP))
        proxy.forwardToTarget(rw, req, targetAddr)
        return
    }

    log.Println(fmt.Sprintf("origin <-> local <-> remote <-> %s(%s)", host, targetIP))
    proxy.forwardToRemoteProxy(rw, req)
}

func (proxy *localProxyServer) forwardToTarget(rw http.ResponseWriter, req *http.Request, targetAddr string) {
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

func (proxy *localProxyServer) forwardToRemoteProxy(rw http.ResponseWriter, req *http.Request) {
    client, _, _ := rw.(http.Hijacker).Hijack()
    var remoteProxy net.Conn
    var err error

    remoteProxyAddr := appendPort(proxy.remoteProxyAddr.Host, proxy.remoteProxyAddr.Scheme)

    if proxy.remoteProxyAddr.Scheme == "https" {
        remoteProxy, err = tls.Dial("tcp", remoteProxyAddr, nil)
    } else {
        remoteProxy, err = net.Dial("tcp", remoteProxyAddr)
    }
    if err != nil {
        return
    }

    req.Header.Set(headerSecret, proxy.secretKey)
    req.Write(remoteProxy)

    go transfer(remoteProxy, client)
    transfer(client, remoteProxy)
}

func (proxy *localProxyServer) pullLatestIPRange(ctx context.Context) error {
    addr := "https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"
    req, _ := http.NewRequestWithContext(ctx, http.MethodGet, addr, nil)
    res, err := proxy.client.Do(req)
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

    proxy.chinaIPRangeDB.Lock()
    defer proxy.chinaIPRangeDB.Unlock()
    proxy.chinaIPRangeDB.db = db
    proxy.chinaIPRangeDB.init()
    sort.Sort(proxy.chinaIPRangeDB)
    return nil
}

func transfer(dst io.WriteCloser, src io.ReadCloser) {
    defer dst.Close()
    defer src.Close()
    io.Copy(dst, src)
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
