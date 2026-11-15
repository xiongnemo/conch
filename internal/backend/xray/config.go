package xray

import "encoding/json"

// The subset of Xray-core's JSON configuration conch emits. Field order
// follows the documentation so generated files read naturally.

type config struct {
	Log         logConfig     `json:"log"`
	API         *apiConfig    `json:"api,omitempty"`
	Stats       *struct{}     `json:"stats,omitempty"`
	Policy      *policyConfig `json:"policy,omitempty"`
	DNS         *dnsConfig    `json:"dns,omitempty"`
	FakeDNS     []fakeDNSPool `json:"fakeDns,omitempty"`
	Inbounds    []inbound     `json:"inbounds"`
	Outbounds   []outbound    `json:"outbounds"`
	Routing     routing       `json:"routing"`
	Observatory *observatory  `json:"observatory,omitempty"`
}

type logConfig struct {
	LogLevel string `json:"loglevel"`
}

type apiConfig struct {
	Tag      string   `json:"tag"`
	Listen   string   `json:"listen,omitempty"`
	Services []string `json:"services"`
}

type apiInboundSettings struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	Network string `json:"network"`
}

type policyConfig struct {
	System policySystem `json:"system"`
}

type policySystem struct {
	StatsInboundUplink    bool `json:"statsInboundUplink"`
	StatsInboundDownlink  bool `json:"statsInboundDownlink"`
	StatsOutboundUplink   bool `json:"statsOutboundUplink"`
	StatsOutboundDownlink bool `json:"statsOutboundDownlink"`
}

type dnsConfig struct {
	Servers       []string `json:"servers"`
	QueryStrategy string   `json:"queryStrategy,omitempty"`
	Tag           string   `json:"tag,omitempty"` // the inbound tag its own queries are routed with
}

type fakeDNSPool struct {
	IPPool   string `json:"ipPool"`
	PoolSize int    `json:"poolSize"`
}

type tunSettings struct {
	Name string `json:"name,omitempty"` // empty: xray picks a free one (utunN on macOS)
	MTU  int    `json:"MTU"`
	// Where xray routes the system into the device itself (not Linux,
	// where conch does): the device's addresses, the routes, and its own
	// connections bound to the physical interface to stay out of it.
	Gateway                []string `json:"gateway,omitempty"`
	DNS                    []string `json:"dns,omitempty"` // Windows: the device's resolver
	AutoSystemRoutingTable []string `json:"autoSystemRoutingTable,omitempty"`
	AutoOutboundsInterface string   `json:"autoOutboundsInterface,omitempty"`
	AutoSystemWfpBlockLeak []string `json:"autoSystemWfpBlockLeak,omitempty"` // Windows
}

type dnsOutboundSettings struct {
	Rules []dnsOutboundRule `json:"rules"`
}

type dnsOutboundRule struct {
	Action string `json:"action"`          // direct | drop | return | hijack
	QType  string `json:"qType,omitempty"` // a port list, e.g. "1,28"
	RCode  int    `json:"rCode,omitempty"` // for return
}

type inbound struct {
	Tag      string    `json:"tag"`
	Protocol string    `json:"protocol"`
	Listen   string    `json:"listen,omitempty"`
	Port     int       `json:"port,omitempty"`
	Settings any       `json:"settings,omitempty"`
	Sniffing *sniffing `json:"sniffing,omitempty"`
}

type sniffing struct {
	Enabled      bool     `json:"enabled"`
	DestOverride []string `json:"destOverride"`
	RouteOnly    bool     `json:"routeOnly"`
}

type outbound struct {
	Tag            string          `json:"tag"`
	Protocol       string          `json:"protocol"`
	Settings       any             `json:"settings,omitempty"`
	StreamSettings *streamSettings `json:"streamSettings,omitempty"`
	TargetStrategy string          `json:"targetStrategy,omitempty"` // how xray resolves the destination before handing it over
}

type streamSettings struct {
	Network             string            `json:"network,omitempty"`
	Security            string            `json:"security,omitempty"`
	TLSSettings         *tlsSettings      `json:"tlsSettings,omitempty"`
	RealitySettings     *realitySettings  `json:"realitySettings,omitempty"`
	RawSettings         *rawSettings      `json:"rawSettings,omitempty"`
	WSSettings          *httpSettings     `json:"wsSettings,omitempty"`
	HTTPUpgradeSettings *httpSettings     `json:"httpupgradeSettings,omitempty"`
	GRPCSettings        *grpcSettings     `json:"grpcSettings,omitempty"`
	KCPSettings         *kcpSettings      `json:"kcpSettings,omitempty"`
	XHTTPSettings       *xhttpSettings    `json:"xhttpSettings,omitempty"`
	HysteriaSettings    *hysteriaSettings `json:"hysteriaSettings,omitempty"`
	MasqueSettings      *masqueSettings   `json:"masqueSettings,omitempty"`
	FinalMask           *finalMask        `json:"finalmask,omitempty"`
	Sockopt             *sockopt          `json:"sockopt,omitempty"`
}

type tlsSettings struct {
	ServerName           string   `json:"serverName,omitempty"`
	ALPN                 []string `json:"alpn,omitempty"`
	Fingerprint          string   `json:"fingerprint,omitempty"`
	PinnedPeerCertSha256 string   `json:"pinnedPeerCertSha256,omitempty"`
	VerifyPeerCertByName string   `json:"verifyPeerCertByName,omitempty"`
	ECHConfigList        string   `json:"echConfigList,omitempty"` // base64, or name+DNS server to look it up
}

type realitySettings struct {
	ServerName  string `json:"serverName,omitempty"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"publicKey"`
	ShortID     string `json:"shortId,omitempty"`
	SpiderX     string `json:"spiderX,omitempty"`
}

type rawSettings struct {
	Header rawHeader `json:"header"`
}

type rawHeader struct {
	Type    string      `json:"type"`
	Request *rawRequest `json:"request,omitempty"`
}

type rawRequest struct {
	Method  string              `json:"method,omitempty"`
	Path    []string            `json:"path,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"`
}

// httpSettings serves both ws and httpupgrade, which share their fields.
type httpSettings struct {
	Host    string            `json:"host,omitempty"`
	Path    string            `json:"path,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

// kcpSettings are mKCP's; zero is xray's default. Packets get their
// checksum or encryption, and their disguise, from finalmask.
type kcpSettings struct {
	MTU              int `json:"mtu,omitempty"`
	TTI              int `json:"tti,omitempty"`
	Uplink           int `json:"uplinkCapacity,omitempty"`
	Downlink         int `json:"downlinkCapacity,omitempty"`
	MaxSendingWindow int `json:"maxSendingWindow,omitempty"` // bytes
}

type grpcSettings struct {
	ServiceName string `json:"serviceName"`
	UserAgent   string `json:"user_agent,omitempty"`
	IdleTimeout int    `json:"idle_timeout,omitempty"` // seconds: the ping interval
}

type xhttpSettings struct {
	Host     string            `json:"host,omitempty"`
	Path     string            `json:"path,omitempty"`
	Mode     string            `json:"mode,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Download *downloadSettings `json:"downloadSettings,omitempty"`
	// Extra are more keys, xray's names already (xPaddingBytes, xmux…).
	Extra map[string]any `json:"-"`
}

func (x xhttpSettings) MarshalJSON() ([]byte, error) {
	type plain xhttpSettings
	b, err := json.Marshal(plain(x))
	if err != nil || len(x.Extra) == 0 {
		return b, err
	}
	m := map[string]any{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	for k, v := range x.Extra {
		m[k] = v
	}
	return json.Marshal(m)
}

// downloadSettings: where XHTTP downloads go, a stream of its own.
type downloadSettings struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	streamSettings
}

type hysteriaSettings struct {
	Version int    `json:"version"`
	Auth    string `json:"auth"`
}

type finalMask struct {
	UDP        []mask      `json:"udp,omitempty"`
	QuicParams *quicParams `json:"quicParams,omitempty"`
}

type mask struct {
	Type     string `json:"type"`
	Settings any    `json:"settings,omitempty"`
}

type quicParams struct {
	Congestion       string `json:"congestion,omitempty"`
	BBRProfile       string `json:"bbrProfile,omitempty"`
	BrutalUp         string `json:"brutalUp,omitempty"`
	BrutalDown       string `json:"brutalDown,omitempty"`
	InitStreamWindow uint64 `json:"initStreamReceiveWindow,omitempty"`
	MaxStreamWindow  uint64 `json:"maxStreamReceiveWindow,omitempty"`
	InitConnWindow   uint64 `json:"initConnectionReceiveWindow,omitempty"`
	MaxConnWindow    uint64 `json:"maxConnectionReceiveWindow,omitempty"`
}

// udpHopSettings are the settings of the "udphop" UDP mask: port hopping.
type udpHopSettings struct {
	Mode        string `json:"mode"`
	Interval    any    `json:"interval,omitempty"` // seconds, or "min-max"; 5 or more; xray's default is 30
	RemotePorts string `json:"remotePorts"`
}

// salamanderSettings: with a packet size range, it is gecko.
type salamanderSettings struct {
	Password   string `json:"password"`
	PacketSize string `json:"packetSize,omitempty"`
}

type sockopt struct {
	DialerProxy    string `json:"dialerProxy,omitempty"`
	DomainStrategy string `json:"domainStrategy,omitempty"`
	TCPFastOpen    bool   `json:"tcpFastOpen,omitempty"`
	TCPMptcp       bool   `json:"tcpMptcp,omitempty"`
	Interface      string `json:"interface,omitempty"`
	Mark           int    `json:"mark,omitempty"`
}

// Outbound settings, in Xray's flat (single server) form.

type serverSettings struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}

type shadowsocksSettings struct {
	serverSettings
	Method   string `json:"method"`
	Password string `json:"password"`
}

type vmessSettings struct {
	serverSettings
	ID          string `json:"id"`
	Security    string `json:"security"`
	Experiments string `json:"experiments,omitempty"`
}

type vlessSettings struct {
	serverSettings
	ID         string `json:"id"`
	Flow       string `json:"flow,omitempty"`
	Encryption string `json:"encryption"`
}

type trojanSettings struct {
	serverSettings
	Password string `json:"password"`
}

type userPassSettings struct {
	serverSettings
	User    string            `json:"user,omitempty"`
	Pass    string            `json:"pass,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

type hysteriaOutSettings struct {
	Version int `json:"version"`
	serverSettings
}

type wireguardSettings struct {
	NoKernelTun bool            `json:"noKernelTun"`
	SecretKey   string          `json:"secretKey"`
	Address     []string        `json:"address,omitempty"`
	Peers       []wireguardPeer `json:"peers"`
	MTU         int             `json:"mtu,omitempty"`
	Reserved    []int           `json:"reserved,omitempty"`
	RemoteDNS   []string        `json:"remoteDNS,omitempty"` // IPs inside the tunnel
}

// noiseSettings: junk packets before a connection's first one.
type noiseSettings struct {
	Noise []noiseItem `json:"noise"`
}

type noiseItem struct {
	Rand string `json:"rand"` // a random size, "min-max" bytes
}

type wireguardPeer struct {
	PublicKey    string   `json:"publicKey"`
	PreSharedKey string   `json:"preSharedKey,omitempty"`
	Endpoint     string   `json:"endpoint"`
	AllowedIPs   []string `json:"allowedIPs,omitempty"`
	KeepAlive    int      `json:"keepAlive,omitempty"`
}

type loopbackSettings struct {
	InboundTag string `json:"inboundTag"`
}

type mixedSettings struct {
	UDP bool `json:"udp"`
}

type routing struct {
	DomainStrategy string     `json:"domainStrategy"`
	Rules          []rule     `json:"rules"`
	Balancers      []balancer `json:"balancers,omitempty"`
}

type rule struct {
	InboundTag  []string `json:"inboundTag,omitempty"`
	Domain      []string `json:"domain,omitempty"`
	IP          []string `json:"ip,omitempty"`
	Process     []string `json:"process,omitempty"`
	Port        string   `json:"port,omitempty"`
	Network     string   `json:"network,omitempty"`
	OutboundTag string   `json:"outboundTag,omitempty"`
	BalancerTag string   `json:"balancerTag,omitempty"`
	RuleTag     string   `json:"ruleTag,omitempty"`
}

type balancer struct {
	Tag         string   `json:"tag"`
	Selector    []string `json:"selector"`
	Strategy    strategy `json:"strategy"`
	FallbackTag string   `json:"fallbackTag,omitempty"`
}

type strategy struct {
	Type string `json:"type"`
}

type observatory struct {
	SubjectSelector   []string `json:"subjectSelector"`
	ProbeURL          string   `json:"probeURL"`
	ProbeInterval     string   `json:"probeInterval"`
	EnableConcurrency bool     `json:"enableConcurrency"`
}

// realmSettings: a Hysteria realm, the rendezvous that finds the server.
type realmSettings struct {
	URL         string       `json:"url"`
	STUNServers []string     `json:"stunServers"`
	TLSConfig   *tlsSettings `json:"tlsConfig,omitempty"`
}

// masqueSettings: MASQUE's transport; warp is Cloudflare WARP's keys.
type masqueSettings struct {
	Host string      `json:"host,omitempty"`
	Path string      `json:"path,omitempty"`
	Warp *masqueWarp `json:"warp,omitempty"`
}

type masqueWarp struct {
	PrivateKey string   `json:"privateKey"`
	PublicKey  string   `json:"publicKey"`
	Address    []string `json:"address"`
}

type masqueOutSettings struct {
	serverSettings
	RemoteDNS []string `json:"remoteDNS,omitempty"`
}
