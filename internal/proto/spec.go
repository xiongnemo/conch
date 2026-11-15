// Package proto describes proxy servers independently of any kernel's
// config format. Nodes are decoded into a Spec from whatever format they
// were written in, and backends with a different native format encode
// from the Spec.
package proto

import (
	"fmt"
	"strconv"
)

// Spec is one proxy server.
type Spec struct {
	Type   string // ss, vmess, vless, trojan, socks5, http, hysteria2, hysteria, tuic, anytls, ssh, wireguard, direct, reject, or the source type if unknown
	Server string
	Port   int
	UDP    bool

	Username   string
	Password   string
	UUID       string
	Cipher     string // shadowsocks method, VMess security
	AlterID    int
	Flow       string // VLESS flow, e.g. xtls-rprx-vision
	Encryption string // VLESS encryption
	UDPOverTCP bool   // shadowsocks UDP-over-TCP
	UoTVersion int    // its version: 1 (mihomo's default) or 2
	// VMess and VLESS: how UDP is carried ("", xudp, packetaddr), and
	// VMess's padding and authenticated length.
	PacketEncoding      string
	GlobalPadding       bool
	AuthenticatedLength bool
	Mux                 *Mux    // sing-mux (mihomo's smux)
	Plugin              *Plugin // shadowsocks SIP003 plugin
	Headers             map[string]string

	TLS       *TLS // nil means no TLS
	Transport Transport

	Hysteria  *Hysteria // hysteria2, and hysteria (v1)
	TUIC      *TUIC
	AnyTLS    *AnyTLS
	SSH       *SSH
	Masque    *Masque
	Snell     *Snell // with Plugin for its obfs-opts
	WireGuard *WireGuard
	TrojanGo  *TrojanGo
	Sockopt   Sockopt

	// Unknown lists source fields that have no neutral meaning (for
	// example a shadowsocks plugin). Backends that cannot honour them
	// must say so instead of silently dropping them.
	Unknown []string
}

type TLS struct {
	SNI         string
	ALPN        []string
	Insecure    bool   // skip certificate verification
	PinSHA256   string // expected certificate sha256, hex
	Fingerprint string // uTLS client fingerprint, e.g. chrome
	Reality     *Reality
	ECH         *ECH
	VerifyName  string // the name the certificate must be for, instead of the SNI
	DisableSNI  bool   // send no SNI (TUIC)
	// A client certificate for mutual TLS: PEM, or a file's path.
	Certificate, PrivateKey string
}

// XHTTPDownload is where XHTTP downloads go, with what mihomo inherits
// from the node filled in.
type XHTTPDownload struct {
	Server     string
	Port       int
	TLS        *TLS
	Path, Host string
	Headers    map[string]string
	Extra      map[string]any // reuse-settings
}

// XHTTPKeys are mihomo's xhttp-opts keys in xray's xhttpSettings.
var XHTTPKeys = map[string]string{
	"no-grpc-header": "noGRPCHeader", "x-padding-bytes": "xPaddingBytes", "x-padding-obfs-mode": "xPaddingObfsMode",
	"x-padding-key": "xPaddingKey", "x-padding-header": "xPaddingHeader", "x-padding-placement": "xPaddingPlacement",
	"x-padding-method": "xPaddingMethod", "uplink-http-method": "uplinkHTTPMethod", "session-placement": "sessionIDPlacement",
	"session-key": "sessionIDKey", "session-table": "sessionIDTable", "session-length": "sessionIDLength",
	"seq-placement": "seqPlacement", "seq-key": "seqKey", "uplink-data-placement": "uplinkDataPlacement",
	"uplink-data-key": "uplinkDataKey", "uplink-chunk-size": "uplinkChunkSize", "sc-max-each-post-bytes": "scMaxEachPostBytes",
	"sc-min-posts-interval-ms": "scMinPostsIntervalMs", "reuse-settings": "xmux",
	// reuse-settings, which is xray's xmux
	"max-concurrency": "maxConcurrency", "max-connections": "maxConnections", "c-max-reuse-times": "cMaxReuseTimes",
	"h-max-request-times": "hMaxRequestTimes", "h-max-reusable-secs": "hMaxReusableSecs", "h-keep-alive-period": "hKeepAlivePeriod",
}

// ECH is Encrypted Client Hello: its config list (base64), or looked up
// in DNS, under another name if QueryServerName says so.
type ECH struct {
	Config          string
	QueryServerName string
}

// Plugin is a shadowsocks plugin as mihomo has them. mihomo's defaults
// are filled in: host bing.com, mux on, shadow-tls version 2 with
// ALPN h2,http/1.1.
type Plugin struct {
	Name        string // obfs, v2ray-plugin, gost-plugin, shadow-tls
	Mode        string // obfs: http or tls; v2ray-plugin, gost-plugin: websocket
	Host        string
	Path        string
	Headers     map[string]string
	Mux         bool // v2ray-plugin, gost-plugin
	HTTPUpgrade bool // v2ray-plugin: HTTPUpgrade instead of WebSocket
	// The plugin's TLS: v2ray-plugin and gost-plugin with tls, and
	// shadow-tls, whose SNI is Host.
	TLS      *TLS
	Password string // shadow-tls
	Version  int    // shadow-tls
}

// Mux is sing-mux: several streams over one connection.
type Mux struct {
	Protocol                               string // h2mux (the default), smux, yamux
	MaxConnections, MinStreams, MaxStreams int
	Padding                                bool
	BrutalUp, BrutalDown                   uint64 // Brutal congestion control, bits per second; 0 is off
}

type Reality struct {
	PublicKey string
	ShortID   string
	SpiderX   string
}

// Transport is how the protocol's stream is carried. The zero value is raw TCP.
type Transport struct {
	Network         string // "", ws, httpupgrade, grpc, xhttp, h2, http, mkcp
	Path            string
	Host            string
	Headers         map[string]string
	ServiceName     string // grpc
	Mode            string // xhttp
	EarlyData       int    // ws: max early data bytes
	EarlyDataHeader string // ws: header carrying early data; empty: in the path
	// TCP with HTTP request headers (network http): the method and every
	// path and host, one of which each request picks; Path and Host are
	// the first. h2 has hosts too.
	Method string
	Paths  []string
	Hosts  []string
	// gRPC
	UserAgent    string
	PingInterval int // seconds
	// XHTTP: mihomo's other xhttp-opts keys as written (XHTTPKeys has
	// xray's names for them), and where downloads go when elsewhere.
	XHTTPExtra map[string]any
	Download   *XHTTPDownload
	KCP        *KCP // mkcp
}

// KCP is mKCP over UDP, mihomo's mkcp-opts; zero values are the defaults
// (mihomo's and xray's are the same).
type KCP struct {
	MTU, TTI                int
	Uplink, Downlink        int // capacity, MB/s
	Congestion              bool
	WriteBuffer, ReadBuffer int // bytes
	// Seed encrypts packets with AES-GCM instead of the plain checksum;
	// Header disguises them (srtp, utp, wechat-video, dtls, wireguard).
	Seed, Header string
}

type Hysteria struct {
	Obfs         string // salamander
	ObfsPassword string
	Up, Down     uint64 // bandwidth hints, bits per second (ParseBandwidth)
	Ports        string // port hopping, e.g. "443,20000-30000"
	HopMin       int    // seconds between hops; a random time up to
	HopMax       int    // HopMax when it is more
	// Hysteria v1: the transport (udp, wechat-video, faketcp), and the
	// auth as base64 bytes when it is not the password string.
	Protocol, Auth string
	// gecko obfuscation pads packets to sizes in this range.
	ObfsMinPacket, ObfsMaxPacket int
	BBRProfile                   string
	Realm                        *Realm // reach the server through a Hysteria realm
	// QUIC flow-control windows, bytes; 0 is the kernel's default.
	InitStreamWindow, MaxStreamWindow, InitConnWindow, MaxConnWindow uint64
}

// Realm is a Hysteria 2 realm: a rendezvous server that brings client and
// server together through NAT, with STUN; TLS is the realm server's.
type Realm struct {
	ServerURL, Token, RealmID string
	STUN                      []string
	TLS                       *TLS
}

// Masque is MASQUE (CONNECT-IP), as Cloudflare WARP has it: the keys
// (base64 DER), the addresses inside, the proxy's URI, h3 or h2, and where
// names are resolved, as in WireGuard.
type Masque struct {
	PrivateKey, PublicKey string
	Address               []string
	URI, Network          string
	DNS                   []string
	RemoteDNS             bool
}

// Snell: the version (mihomo has 1 to 4, and reads 5 as 4) and whether
// connections are reused. Password is the PSK.
type Snell struct {
	Version int
	Reuse   bool
}

// TUIC v5 (UUID and Password), or v4 with a token.
type TUIC struct {
	Token         string
	Congestion    string // cubic, new_reno, bbr…
	UDPRelayMode  string // native, quic
	UDPOverStream bool
	ReduceRTT     bool // 0-RTT
	Heartbeat     int  // milliseconds
}

type AnyTLS struct {
	IdleCheck, IdleTimeout int // seconds
	MinIdle                int
}

// SSH: a private key, PEM or a file's path, and the host keys to trust.
type SSH struct {
	PrivateKey, Passphrase      string
	HostKeys, HostKeyAlgorithms []string
}

// TrojanGo holds what trojan-go adds to trojan; such nodes run in a
// trojan-go sidecar.
type TrojanGo struct {
	SSMethod   string // an extra shadowsocks AEAD layer inside the TLS stream
	SSPassword string
	Mux        bool
}

type WireGuard struct {
	PrivateKey string
	Address    []string // interface addresses, e.g. 10.0.0.2/32
	MTU        int
	Peers      []WireGuardPeer
	Keepalive  int // seconds between keepalives; 0 is none
	Workers    int
	// Where destinations' names are resolved: by these DNS servers through
	// the tunnel when RemoteDNS, otherwise locally, as mihomo does.
	DNS       []string
	RemoteDNS bool
	// AmneziaWG's options, as mihomo's amnezia-wg-option has them.
	Amnezia map[string]any
}

// AmneziaJunk is what of AmneziaWG plain WireGuard servers accept too:
// junk packets before the handshake (jc of jmin to jmax bytes). ok is
// false when the options change the protocol itself.
func (w *WireGuard) AmneziaJunk() (jc, jmin, jmax int, ok bool) {
	for k, v := range w.Amnezia {
		n, _ := strconv.Atoi(fmt.Sprint(v))
		switch k {
		case "jc":
			jc = n
		case "jmin":
			jmin = n
		case "jmax":
			jmax = n
		case "h1", "h2", "h3", "h4":
			if n != 0 && fmt.Sprint(n) != k[1:] { // 1 to 4 are WireGuard's own
				return 0, 0, 0, false
			}
		case "s1", "s2", "s3", "s4", "itime", "version":
			if n != 0 {
				return 0, 0, 0, false
			}
		default:
			if b, isBool := v.(bool); !isBool || b {
				if s := fmt.Sprint(v); s != "" && s != "0" && s != "false" {
					return 0, 0, 0, false
				}
			}
		}
	}
	return jc, jmin, jmax, true
}

type WireGuardPeer struct {
	Server       string
	Port         int
	PublicKey    string
	PreSharedKey string
	Reserved     []int
	AllowedIPs   []string
}

type Sockopt struct {
	TFO       bool
	MPTCP     bool
	Interface string
	Mark      int
	IPVersion string // ipv4, ipv6, ipv4-prefer, ipv6-prefer, dual
}
