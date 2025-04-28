module github.com/nihiloid/hazetunnel/hazetunnel

go 1.24.1

replace golang.org/x/net => github.com/nihiloid/x-net v0.0.1 // shuffle

replace github.com/refraction-networking/utls => github.com/nihiloid/utls v0.0.1 // minimum randomized TLS version 1.2 when maximum TLS is 1.3

//replace golang.org/x/net => /Users/nihiloid/IdeaProjects/x-net

require (
	github.com/cloudflare/cfssl v1.6.5
	github.com/cristalhq/base64 v0.1.2
	github.com/elazarl/goproxy v0.0.0-20231117061959-7cc037d33fb5
	github.com/goccy/go-json v0.10.3
	github.com/mileusna/useragent v1.3.4
	github.com/refraction-networking/utls v1.7.1
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2 v2.9.2
)

require (
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/cloudflare/circl v1.5.0 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/google/certificate-transparency-go v1.2.1 // indirect
	github.com/jmoiron/sqlx v1.4.0 // indirect
	github.com/klauspost/compress v1.17.8 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/weppos/publicsuffix-go v0.30.2 // indirect
	github.com/zmap/zcrypto v0.0.0-20240512203510-0fef58d9a9db // indirect
	github.com/zmap/zlint/v3 v3.6.2 // indirect
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/net v0.38.0 // indirect
	golang.org/x/sys v0.32.0 // indirect
	golang.org/x/text v0.24.0 // indirect
	google.golang.org/protobuf v1.34.1 // indirect
	k8s.io/klog/v2 v2.120.1 // indirect
)
