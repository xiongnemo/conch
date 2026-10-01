package xray

// The subset of Xray-core's JSON configuration nautilus emits. Field order
// follows the documentation so generated files read naturally.

type config struct {
	Log         logConfig     `json:"log"`
	API         *apiConfig    `json:"api,omitempty"`
	Stats       *struct{}     `json:"stats,omitempty"`
	Policy      *policyConfig `json:"policy,omitempty"`
	DNS         *dnsConfig    `json:"dns,omitempty"`
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
	XHTTPSettings       *xhttpSettings    `json:"xhttpSettings,omitempty"`
	HysteriaSettings    *hysteriaSettings `json:"hysteriaSettings,omitempty"`
	FinalMask           *finalMask        `json:"finalmask,omitempty"`
	Sockopt             *sockopt          `json:"sockopt,omitempty"`
}

type tlsSettings struct {
	ServerName           string   `json:"serverName,omitempty"`
	ALPN                 []string `json:"alpn,omitempty"`
	Fingerprint          string   `json:"fingerprint,omitempty"`
	PinnedPeerCertSha256 string   `json:"pinnedPeerCertSha256,omitempty"`
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
	Path    []string            `json:"path,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"`
}

// httpSettings serves both ws and httpupgrade, which share their fields.
type httpSettings struct {
	Host    string            `json:"host,omitempty"`
	Path    string            `json:"path,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

type grpcSettings struct {
	ServiceName string `json:"serviceName"`
}

type xhttpSettings struct {
	Host    string            `json:"host,omitempty"`
	Path    string            `json:"path,omitempty"`
	Mode    string            `json:"mode,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
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
	Congestion string  `json:"congestion,omitempty"`
	BrutalUp   string  `json:"brutalUp,omitempty"`
	BrutalDown string  `json:"brutalDown,omitempty"`
	UDPHop     *udpHop `json:"udpHop,omitempty"`
}

type udpHop struct {
	Ports    string `json:"ports"`
	Interval int    `json:"interval,omitempty"`
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
	UoT      bool   `json:"uot,omitempty"`
}

type vmessSettings struct {
	serverSettings
	ID       string `json:"id"`
	Security string `json:"security"`
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
	SecretKey string          `json:"secretKey"`
	Address   []string        `json:"address,omitempty"`
	Peers     []wireguardPeer `json:"peers"`
	MTU       int             `json:"mtu,omitempty"`
	Reserved  []int           `json:"reserved,omitempty"`
}

type wireguardPeer struct {
	PublicKey    string   `json:"publicKey"`
	PreSharedKey string   `json:"preSharedKey,omitempty"`
	Endpoint     string   `json:"endpoint"`
	AllowedIPs   []string `json:"allowedIPs,omitempty"`
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
