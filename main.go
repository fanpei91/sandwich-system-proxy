package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/robfig/cron/v3"
	"github.com/sevlyar/go-daemon"
)

type options struct {
	remoteProxyMode          bool
	remoteProxyAddr          string
	listenAddr               string
	certFile                 string
	privateKeyFile           string
	secretKey                string
	reversedWebsite          string
	disableAutoCrossFirewall bool
	staticTTLInSeconds       int
	rateLimit                bool
	listenMode               string
}

var (
	flags options
)

func main() {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
	log.SetOutput(os.Stdout)

	workDir := filepath.Join(os.Getenv("HOME"), ".sandwich")
	logFile := filepath.Join(workDir, "sandwich.log")

	flag.BoolVar(&flags.remoteProxyMode, "remote-proxy-mode", false, "remote proxy mode")
	flag.StringVar(&flags.remoteProxyAddr, "remote-proxy-addr", "https://yourdomain.com:443", "the remote proxy address to connect to")
	flag.StringVar(&flags.listenAddr, "listen-addr", "127.0.0.1:2286", "listens on given address")
	flag.StringVar(&flags.certFile, "cert-file", "", "cert file path")
	flag.StringVar(&flags.privateKeyFile, "private-key-file", "", "private key file path")
	flag.StringVar(&flags.secretKey, "secret-key", "secret key", "secrect key to cross firewall")
	flag.StringVar(&flags.reversedWebsite, "reversed-website", "http://mirror.siena.edu/ubuntu/", "reversed website to fool firewall")
	flag.BoolVar(&flags.disableAutoCrossFirewall, "disable-auto-cross-firewall", false, "disable auto cross firewall")
	flag.IntVar(&flags.staticTTLInSeconds, "static-dns-ttl", 86400, "use static dns ttl")
	flag.BoolVar(&flags.rateLimit, "rate-limit", false, "rate limit")
	flag.StringVar(&flags.listenMode, "listen-mode", "default", "lient mode, includes all and default. all:  listen for All activated network services")
	flag.Parse()

	daemon.SetSigHandler(termHandler, syscall.SIGQUIT, syscall.SIGTERM)

	os.MkdirAll(workDir, 0755)

	cntxt := &daemon.Context{
		PidFileName: filepath.Join(workDir, "sandwich.pid"),
		PidFilePerm: 0644,
		LogFileName: logFile,
		LogFilePerm: 0640,
		Umask:       027,
		Args:        nil,
	}

	if len(daemon.ActiveFlags()) > 0 {
		d, err := cntxt.Search()
		if err != nil {
			log.Fatalf("error: unable send signal to the daemon: %s", err.Error())
		}
		daemon.SendCommands(d)
		return
	}

	d, err := cntxt.Reborn()
	if err != nil {
		log.Fatalf("error: %s", strings.ToLower(err.Error()))
	}
	if d != nil {
		return
	}
	defer cntxt.Release()

	var listener net.Listener
	if listener, err = net.Listen("tcp", flags.listenAddr); err != nil {
		log.Fatalf("error: %s", err.Error())
	}

	var errCh = make(chan error, 2)
	if flags.remoteProxyMode {
		go startRemoteProxy(flags, listener, errCh)
	} else {
		go startLocalProxy(flags, listener, errCh)
	}

	select {
	case err := <-errCh:
		log.Fatalf("error: %s", err)
	default:
	}
	if err = daemon.ServeSignals(); err != nil {
		log.Fatalf("error: %s", strings.ToLower(err.Error()))
	}
}

func startLocalProxy(o options, listener net.Listener, errChan chan<- error) {
	var err error
	u, err := url.Parse(o.remoteProxyAddr)
	if err != nil {
		errChan <- err
		return
	}

	h := make(http.Header, 0)
	h.Set(headerSecret, o.secretKey)

	client := &http.Client{
		Timeout: time.Second * 3,
		Transport: &http.Transport{
			Proxy: func(request *http.Request) (i *url.URL, e error) {
				request.Header.Set(headerSecret, o.secretKey)
				return u, nil
			},
			TLSClientConfig:    &tls.Config{InsecureSkipVerify: false},
			ProxyConnectHeader: h,
		},
	}

	dns := newSmartDNS(
		(&dnsOverHostsFile{}).lookup,
		(&dnsOverHTTPS{
			client:    client,
			staticTTL: time.Duration(o.staticTTLInSeconds) * time.Second,
		}).lookup,
		(&dnsOverUDP{}).lookup,
	)

	local := &localProxy{
		remoteProxyAddr:   u,
		secretKey:         o.secretKey,
		chinaIPRangeDB:    newChinaIPRangeDB(),
		autoCrossFirewall: !o.disableAutoCrossFirewall,
		client:            client,
		dns:               dns,
	}

	ctx, cancel := context.WithCancel(context.Background())

	setSysProxy(o.listenAddr, o.listenMode)

	s := cron.New()
	s.AddFunc("@every 4h", func() {
		local.pullLatestIPRange(ctx)
	})
	s.Start()

	defer cancel()

	errChan <- http.Serve(listener, local)
}

func startRemoteProxy(o options, listener net.Listener, errChan chan<- error) {
	var err error
	r := &remoteProxy{
		rateLimit:       o.rateLimit,
		secretKey:       o.secretKey,
		reversedWebsite: o.reversedWebsite,
	}
	if o.certFile != "" && o.privateKeyFile != "" {
		err = http.ServeTLS(listener, r, o.certFile, o.privateKeyFile)
	} else {
		err = http.Serve(listener, r)
	}
	errChan <- err
}

func termHandler(_ os.Signal) (err error) {
	unsetSysProxy(flags.listenMode)
	return daemon.ErrStop
}
