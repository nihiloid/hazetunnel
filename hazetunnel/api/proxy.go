package api

import (
	"context"
	utls "github.com/refraction-networking/utls"
	sf "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/utls"
	"log"
	"net/http"
	"net/url"
	"sync"

	"github.com/elazarl/goproxy"
)

type contextKey string

const payloadKey contextKey = "payload"

type ProxyInstance struct {
	Server *http.Server
	Cancel context.CancelFunc
}

// Globals
var (
	serverMux        sync.Mutex
	proxyInstanceMap = make(map[string]*ProxyInstance)
)

func initServer(Flags *ProxySetup) *http.Server {
	serverMux.Lock()
	defer serverMux.Unlock()

	// Load CA if not already loaded
	loadCA()

	// Setup the proxy instance
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = Config.Verbose
	setupProxy(proxy, Flags)

	// Create the server
	server := &http.Server{
		Addr:    Flags.Addr + ":" + Flags.Port,
		Handler: proxy,
	}
	_, cancel := context.WithCancel(context.Background())

	// Add proxy instance to the map
	proxyInstanceMap[Flags.Id] = &ProxyInstance{
		Server: server,
		Cancel: cancel,
	}
	return server
}

func setupProxy(proxy *goproxy.ProxyHttpServer, Flags *ProxySetup) {
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	proxy.OnRequest().DoFunc(
		func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			var upstreamProxy *url.URL
			clientHelloId := utls.HelloRandomizedALPN
			utls.DefaultWeights = utls.Weights{
				Extensions_Append_ALPN:                             0.7,
				TLSVersMax_Set_VersionTLS13:                        1.0, // 0.4 default
				CipherSuites_Remove_RandomCiphers:                  0.4,
				SigAndHashAlgos_Append_ECDSAWithSHA1:               0.63,
				SigAndHashAlgos_Append_ECDSAWithP521AndSHA512:      0.59,
				SigAndHashAlgos_Append_PSSWithSHA256:               0.51,
				SigAndHashAlgos_Append_PSSWithSHA384_PSSWithSHA512: 0.9,
				CurveIDs_Append_X25519:                             0.71,
				CurveIDs_Append_CurveP521:                          0.46,
				Extensions_Append_Padding:                          0.62,
				Extensions_Append_Status:                           0.74,
				Extensions_Append_SCT:                              0.46,
				Extensions_Append_Reneg:                            0.75,
				Extensions_Append_EMS:                              0.77,
				FirstKeyShare_Set_CurveP256:                        0.25,
				Extensions_Append_ALPS:                             0.33,
			}

			// Store the payload code in the request's context
			ctx.Req = req.WithContext(
				context.WithValue(
					ctx.Req.Context(),
					payloadKey,
					Flags.Payload,
				),
			)

			// If a proxy header was passed, set it to upstreamProxy
			if len(Flags.UpstreamProxy) != 0 {
				proxyUrl, err := url.Parse(Flags.UpstreamProxy)
				if err != nil {
					return req, invalidUpstreamProxyResponse(req, ctx, Flags.UpstreamProxy)
				}
				upstreamProxy = proxyUrl
			}

			// Skip TLS handshake if scheme is HTTP
			ctx.Logf("Scheme: %s", req.URL.Scheme)
			if req.URL.Scheme == "http" {
				ctx.Logf("Skipping TLS for HTTP request")
				return req, nil
			}

			// Build round tripper
			roundTripper := sf.NewUTLSHTTPRoundTripperWithProxy(clientHelloId, &utls.Config{
				InsecureSkipVerify: true,
				OmitEmptyPsk:       true,
			}, http.DefaultTransport, false, upstreamProxy)

			ctx.RoundTripper = goproxy.RoundTripperFunc(
				func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Response, error) {
					return roundTripper.RoundTrip(req)
				})

			return req, nil
		},
	)

	// Inject payload code into responses
	proxy.OnResponse().DoFunc(PayloadInjector)
}

// Launches the server
func Launch(Flags *ProxySetup) {
	server := initServer(Flags)

	// Print server startup message if from CLI or verbose CFFI
	if Flags.Id == "cli" || Config.Verbose {
		log.Println("Hazetunnel listening at", server.Addr)
	}
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("HTTP server ListenAndServe: %v", err)
	}
}
