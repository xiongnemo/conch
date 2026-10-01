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
	Headers    map[string]string

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
	EarlyDataHeader string // ws: header carrying early data
}

type Hysteria struct {
	Obfs         string // salamander
	ObfsPassword string
	Up, Down     string // bandwidth, e.g. "100 mbps"
	Ports        string // port hopping, e.g. "20000-30000"
	HopInterval  int    // seconds
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
