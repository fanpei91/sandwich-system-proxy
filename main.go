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

var Version = "unknown"

type LocalProxyFlags struct {
	listenAddr                    string
	remoteProxyAddr               string
	remoteProxyTransport          string
	dnsOverHttpsProvider          string
	forceForwardToRemoteProxy     bool
	secretKey                     string
	pullLatestIPDBDurationInHours int
}

type RemoteProxyFlags struct {
	domain                 string
	certCacheDir           string
	staticReversedUrl      string
	enableWebsiteRatelimit bool
	enableQUIC             bool
	quicListenAddr         string
	secretKey              string
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
				Name:        "remote-proxy-transport",
				Value:       transportAuto,
				Usage:       "transport to the remote proxy: auto (QUIC with HTTPS fallback), quic or https",
				Destination: &localProxyFlags.remoteProxyTransport,
			},
			&cli.StringFlag{
				Name:        "dns-over-https-provider",
				Value:       "https://doh.360.cn/dns-query",
				Usage:       "DNS over HTTPS provider",
				Destination: &localProxyFlags.dnsOverHttpsProvider,
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
			&cli.BoolFlag{
				Name:        "enable-quic",
				Value:       true,
				Usage:       "serve the QUIC tunnel on --quic-listen-addr/udp",
				Destination: &remoteProxyFlags.enableQUIC,
			},
			&cli.StringFlag{
				Name:        "quic-listen-addr",
				Value:       ":443",
				Usage:       "UDP listen address for QUIC (port must not clash with TCP 443)",
				Destination: &remoteProxyFlags.quicListenAddr,
			},
			&cli.StringFlag{
				Name:        "secret-key",
				Value:       "<your secret key>",
				Usage:       "secret key",
				Destination: &remoteProxyFlags.secretKey,
			},
		},
		Action: remoteProxyServerCmdAction,
	}

	versionCmd := &cli.Command{
		Name:  "version",
		Usage: "print the git commit the binary was built from",
		Action: func(c *cli.Context) error {
			fmt.Println(Version)
			return nil
		},
	}

	app := &cli.App{
		Commands: []*cli.Command{
			localProxyCmd,
			remoteProxyCmd,
			versionCmd,
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
			provider: localProxyFlags.dnsOverHttpsProvider,
		},
		&dnsOverUDP{},
	)

	transport, err := newRemoteTransportSelector(u, localProxyFlags.secretKey, localProxyFlags.remoteProxyTransport)
	if err != nil {
		return errors.New("set up remote proxy transport error: " + err.Error())
	}
	defer transport.close()

	localProxy := &localProxyServer{
		transport:                 transport,
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
	remoteProxy := &remoteProxyServer{
		enableWebsiteRatelimit: remoteProxyFlags.enableWebsiteRatelimit,
		secretKey:              remoteProxyFlags.secretKey,
		staticReversedAddr:     remoteProxyFlags.staticReversedUrl,
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

	if remoteProxyFlags.enableQUIC {
		quicServer, err := newQUICRemoteProxyServer(
			remoteProxyFlags.quicListenAddr,
			remoteProxyFlags.secretKey,
			tlsConfig,
		)
		if err != nil {
			// Losing UDP must not take the TCP side down: old local proxies and
			// the masquerade website keep working.
			log.Printf("failed to start QUIC server on %s/udp, serving TCP only: %v", remoteProxyFlags.quicListenAddr, err)
		} else {
			defer quicServer.Close()
			go func() {
				log.Printf("Starting QUIC tunnel server on %s/udp", quicServer.Addr())
				if err := quicServer.Serve(); err != nil {
					log.Printf("QUIC server stopped: %v", err)
				}
			}()
		}
	}

	s := &http.Server{Addr: ":443", TLSConfig: tlsConfig, Handler: remoteProxy}
	defer s.Close()

	log.Println("Starting HTTPS server on :443")
	if err := s.ListenAndServeTLS("", ""); err != nil {
		return fmt.Errorf("start HTTPS server on :443 error: %v", err)
	}
	return nil
}
