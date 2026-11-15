// Package proto describes proxy servers independently of any kernel's
// config format. Nodes are decoded into a Spec from whatever format they
// were written in, and backends with a different native format encode
// from the Spec.
package proto

// Spec is one proxy server.
type Spec struct {
	Type   string // ss, vmess, vless, trojan, socks5, http, hysteria2, wireguard, or the source type if unknown
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
	Mux                 *Mux // sing-mux (mihomo's smux)
	Headers             map[string]string

	TLS       *TLS // nil means no TLS
	Transport Transport

	Hysteria  *Hysteria
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
	// A client certificate for mutual TLS: PEM, or a file's path.
	Certificate, PrivateKey string
}

// ECH is Encrypted Client Hello: its config list (base64), or looked up
// in DNS, under another name if QueryServerName says so.
type ECH struct {
	Config          string
	QueryServerName string
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
	Network         string // "", ws, httpupgrade, grpc, xhttp, h2, http
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
}

type Hysteria struct {
	Obfs         string // salamander
	ObfsPassword string
	Up, Down     uint64 // bandwidth hints, bits per second (ParseBandwidth)
	Ports        string // port hopping, e.g. "443,20000-30000"
	HopMin       int    // seconds between hops; a random time up to
	HopMax       int    // HopMax when it is more
	// gecko obfuscation pads packets to sizes in this range.
	ObfsMinPacket, ObfsMaxPacket int
	BBRProfile                   string
	// QUIC flow-control windows, bytes; 0 is the kernel's default.
	InitStreamWindow, MaxStreamWindow, InitConnWindow, MaxConnWindow uint64
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
