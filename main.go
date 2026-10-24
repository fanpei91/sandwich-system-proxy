package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/robfig/cron/v3"
	"github.com/urfave/cli/v2"
)

type LocalProxyFlags struct {
	listenAddr                    string
	remoteProxyAddr               string
	dnsOverHttpsProvider          string
	staticDnsTTLInSeconds         int
	forceForwardToRemoteProxy     bool
	secretKey                     string
	pullLatestIPDBDurationInHours int
}

type RemoteProxyFlags struct {
	domain                            string
	certCacheDir                      string
	staticReversedUrl                 string
	enableWebsiteRatelimit            bool
	secretKey                         string
	outboundProxy                     string
	outboundProxyMode                 string
	outboundProxyFallbackTTLInSeconds int
}

var (
	localProxyFlags  LocalProxyFlags
	remoteProxyFlags RemoteProxyFlags
)

func main() {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
	log.SetOutput(os.Stdout)

	localProxyCmd := &cli.Command{
		Name:  "start-local-proxy-server",
		Usage: "Start local proxy server",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "listen-addr",
				Value:       "127.0.0.1:5686",
				Usage:       "listen address",
				Destination: &localProxyFlags.listenAddr,
			},
			&cli.StringFlag{
				Name:        "remote-proxy-addr",
				Value:       "https://yourdomain.com",
				Usage:       "remote proxy address",
				Destination: &localProxyFlags.remoteProxyAddr,
			},
			&cli.StringFlag{
				Name:        "dns-over-https-provider",
				Value:       "https://doh.360.cn/dns-query",
				Usage:       "DNS over HTTPS provider",
				Destination: &localProxyFlags.dnsOverHttpsProvider,
			},
			&cli.IntFlag{
				Name:        "static-dns-ttl-seconds",
				Value:       86400,
				Usage:       "static DNS TTL in seconds",
				Destination: &localProxyFlags.staticDnsTTLInSeconds,
			},
			&cli.BoolFlag{
				Name:        "force-forward-to-remote-proxy",
				Value:       false,
				Usage:       "force forward all requests to remote proxy",
				Destination: &localProxyFlags.forceForwardToRemoteProxy,
			},

			&cli.IntFlag{
				Name:        "pull-latest-ipdb-interval-in-hours",
				Value:       24,
				Usage:       "internal(hours) of pulling the latest IP database",
				Destination: &localProxyFlags.pullLatestIPDBDurationInHours,
			},

			&cli.StringFlag{
				Name:        "secret-key",
				Value:       "<your secret key>",
				Usage:       "secret key required by remote proxy",
				Destination: &localProxyFlags.secretKey,
			},
		},
		Action: localProxyServerCmdAction,
	}

	remoteProxyCmd := &cli.Command{
		Name:  "start-remote-proxy-server",
		Usage: "Start remote proxy server",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "domain",
				Value:       "yourdomain.com",
				Usage:       "domain to access to certificates from Let's Encrypt",
				Destination: &remoteProxyFlags.domain,
			},
			&cli.StringFlag{
				Name:        "cert-cache-dir",
				Value:       "certs",
				Usage:       "directory to stores and retrieves previously-obtained certificates",
				Destination: &remoteProxyFlags.certCacheDir,
			},
			&cli.StringFlag{
				Name:        "static-reversed-url",
				Value:       "https://mirrors.teamcloud.am",
				Usage:       "static reversed url",
				Destination: &remoteProxyFlags.staticReversedUrl,
			},
			&cli.BoolFlag{
				Name:        "enable-website-ratelimit",
				Value:       true,
				Usage:       "enable rate limiting for website",
				Destination: &remoteProxyFlags.enableWebsiteRatelimit,
			},
			&cli.StringFlag{
				Name:        "secret-key",
				Value:       "<your secret key>",
				Usage:       "secret key",
				Destination: &remoteProxyFlags.secretKey,
			},
			&cli.StringFlag{
				Name:        "outbound-socks5-proxy",
				Value:       "",
				Usage:       "SOCKS5 proxy used to reach targets (e.g. socks5://user:pass@127.0.0.1:40000 | socks5://127.0.0.1:40000)",
				Destination: &remoteProxyFlags.outboundProxy,
			},
			&cli.StringFlag{
				Name:        "outbound-proxy-mode",
				Value:       string(outboundProxyModeFallback),
				Usage:       `how to use the outbound SOCKS5 proxy: "fallback" only after a direct connection is reset, "always" forward every request`,
				Destination: &remoteProxyFlags.outboundProxyMode,
			},
			&cli.IntFlag{
				Name:        "outbound-proxy-fallback-ttl-seconds",
				Value:       86400,
				Usage:       "TTL in seconds for hosts that fall back to the outbound SOCKS5 proxy",
				Destination: &remoteProxyFlags.outboundProxyFallbackTTLInSeconds,
			},
		},
		Action: remoteProxyServerCmdAction,
	}

	app := &cli.App{
		Commands: []*cli.Command{
			localProxyCmd,
			remoteProxyCmd,
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatalf("failed to run app: %s", err.Error())
	}
}

func localProxyServerCmdAction(_ *cli.Context) error {
	var listener net.Listener
	var err error

	if listener, err = net.Listen("tcp", localProxyFlags.listenAddr); err != nil {
		return errors.New("listen on local proxy address error: " + err.Error())
	}

	u, err := url.Parse(localProxyFlags.remoteProxyAddr)
	if err != nil {
		return errors.New("parse remote proxy address error: " + err.Error())
	}

	h := make(http.Header)
	h.Set(headerSecret, localProxyFlags.secretKey)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(request *http.Request) (i *url.URL, e error) {
				request.Header.Set(headerSecret, localProxyFlags.secretKey)
				return u, nil
			},
			TLSClientConfig:    &tls.Config{InsecureSkipVerify: false},
			ProxyConnectHeader: h,
		},
	}

	dns := newCachedDNS(
		&dnsOverHostsFile{},
		&dnsOverHTTPS{
			provider:  localProxyFlags.dnsOverHttpsProvider,
			staticTTL: time.Duration(localProxyFlags.staticDnsTTLInSeconds) * time.Second,
		},
		&dnsOverUDP{},
	)

	localProxy := &localProxyServer{
		remoteProxyAddr:           u,
		secretKey:                 localProxyFlags.secretKey,
		chinaIPRangeDB:            newChinaIPRangeDB(),
		forceForwardToRemoteProxy: localProxyFlags.forceForwardToRemoteProxy,
		client:                    client,
		dns:                       dns,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := setSysProxy(localProxyFlags.listenAddr); err != nil {
		log.Printf("failed to set sys proxy to %s: %s", localProxyFlags.listenAddr, err)
		return err
	}

	s := cron.New()
	s.AddFunc(fmt.Sprintf("@every %dh", localProxyFlags.pullLatestIPDBDurationInHours), func() {
		log.Printf("start pulling the latest IP database at %s", time.Now())
		if err := localProxy.pullLatestIPRange(ctx); err != nil {
			log.Printf("failed to pull the latest IP database: %s, time: %s", err, time.Now())
		}
		log.Printf("end pulling the latest IP database at %s", time.Now())
	})
	s.Start()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigs
		unsetSysProxy()
		os.Exit(0)
	}()

	if err = http.Serve(listener, localProxy); err != nil {
		return errors.New("start HTTP server error: " + err.Error())
	}

	return nil
}

func remoteProxyServerCmdAction(_ *cli.Context) error {
	outboundProxy, err := parseOutboundProxy(remoteProxyFlags.outboundProxy)
	if err != nil {
		return fmt.Errorf("parse outbound SOCKS5 proxy error: %v", err)
	}

	outboundProxyMode, err := parseOutboundProxyMode(remoteProxyFlags.outboundProxyMode)
	if err != nil {
		return fmt.Errorf("parse outbound proxy mode error: %v", err)
	}
	if outboundProxyMode == outboundProxyModeAlways && outboundProxy == nil {
		return errors.New("outbound proxy mode \"always\" requires --outbound-socks5-proxy")
	}

	if remoteProxyFlags.outboundProxyFallbackTTLInSeconds <= 0 {
		return errors.New("outbound proxy fallback TTL must be greater than 0")
	}

	remoteProxy := &remoteProxyServer{
		enableWebsiteRatelimit: remoteProxyFlags.enableWebsiteRatelimit,
		secretKey:              remoteProxyFlags.secretKey,
		staticReversedAddr:     remoteProxyFlags.staticReversedUrl,
		outboundProxy:          outboundProxy,
		outboundProxyMode:      outboundProxyMode,
		fallbackHosts:          newFallbackHosts(time.Duration(remoteProxyFlags.outboundProxyFallbackTTLInSeconds) * time.Second),
	}

	if err := os.MkdirAll(remoteProxyFlags.certCacheDir, 0700); err != nil {
		return fmt.Errorf("create cert cache dir %s error: %v", remoteProxyFlags.certCacheDir, err)
	}

	m := &autocert.Manager{
		Cache:      autocert.DirCache(remoteProxyFlags.certCacheDir),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(remoteProxyFlags.domain),
	}

	tlsConfig := &tls.Config{
		GetCertificate: m.GetCertificate,
		NextProtos: []string{
			acme.ALPNProto,
		},
	}

	s := &http.Server{Addr: ":443", TLSConfig: tlsConfig, Handler: remoteProxy}
	defer s.Close()

	log.Println("Starting HTTPS server on :443")
	if err := s.ListenAndServeTLS("", ""); err != nil {
		return fmt.Errorf("start HTTPS server on :443 error: %v", err)
	}
	return nil
}
