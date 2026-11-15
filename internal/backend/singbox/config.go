package singbox

// The subset of sing-box 1.14's JSON configuration conch emits. sing-box
// rejects unknown keys, so only fields it knows are declared here.

type config struct {
	Log          logConfig     `json:"log"`
	DNS          *dnsConfig    `json:"dns,omitempty"`
	Endpoints    []endpoint    `json:"endpoints,omitempty"`
	Inbounds     []inbound     `json:"inbounds"`
	Outbounds    []outbound    `json:"outbounds"`
	Route        routing       `json:"route"`
	Experimental *experimental `json:"experimental,omitempty"`
}

type logConfig struct {
	Level     string `json:"level,omitempty"`
	Disabled  bool   `json:"disabled,omitempty"`
	Timestamp bool   `json:"timestamp,omitempty"`
}

type dnsConfig struct {
	Servers  []dnsServer `json:"servers"`
	Rules    []dnsRule   `json:"rules,omitempty"`
	Final    string      `json:"final,omitempty"`
	Strategy string      `json:"strategy,omitempty"`
}

type dnsServer struct {
	Type           string `json:"type"`
	Tag            string `json:"tag"`
	Server         string `json:"server,omitempty"`
	ServerPort     int    `json:"server_port,omitempty"`
	Path           string `json:"path,omitempty"`
	DomainResolver string `json:"domain_resolver,omitempty"`
	Inet4Range     string `json:"inet4_range,omitempty"`
	Inet6Range     string `json:"inet6_range,omitempty"`
}

type dnsRule struct {
	Inbound   []string `json:"inbound,omitempty"`
	QueryType []string `json:"query_type,omitempty"`
	Server    string   `json:"server"`
}

type inbound struct {
	Type        string   `json:"type"`
	Tag         string   `json:"tag"`
	Listen      string   `json:"listen,omitempty"`
	ListenPort  int      `json:"listen_port,omitempty"`
	Address     []string `json:"address,omitempty"`
	AutoRoute   bool     `json:"auto_route,omitempty"`
	StrictRoute bool     `json:"strict_route,omitempty"`
	Stack       string   `json:"stack,omitempty"`
}

// outbound is every kind of outbound conch emits; each kind uses some
// of the fields.
type outbound struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Server     string `json:"server,omitempty"`
	ServerPort int    `json:"server_port,omitempty"`

	Version        string            `json:"version,omitempty"` // socks
	Method         string            `json:"method,omitempty"`  // shadowsocks
	Username       string            `json:"username,omitempty"`
	Password       string            `json:"password,omitempty"`
	UUID           string            `json:"uuid,omitempty"`
	Security       string            `json:"security,omitempty"` // vmess
	AlterID        int               `json:"alter_id,omitempty"`
	Flow           string            `json:"flow,omitempty"` // vless
	PacketEncoding string            `json:"packet_encoding,omitempty"`
	GlobalPadding  bool              `json:"global_padding,omitempty"` // vmess
	AuthLength     bool              `json:"authenticated_length,omitempty"`
	UDPOverTCP     *udpOverTCP       `json:"udp_over_tcp,omitempty"`
	Multiplex      *multiplex        `json:"multiplex,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"` // http

	ServerPorts    []string `json:"server_ports,omitempty"` // hysteria2
	HopInterval    string   `json:"hop_interval,omitempty"`
	HopIntervalMax string   `json:"hop_interval_max,omitempty"`
	UpMbps         int      `json:"up_mbps,omitempty"`
	DownMbps       int      `json:"down_mbps,omitempty"`
	Obfs           *obfs    `json:"obfs,omitempty"`
	BBRProfile     string   `json:"bbr_profile,omitempty"`
	StreamWindow   uint64   `json:"stream_receive_window,omitempty"`
	ConnWindow     uint64   `json:"connection_receive_window,omitempty"`

	Outbounds   []string `json:"outbounds,omitempty"` // selector, urltest
	Default     string   `json:"default,omitempty"`
	URL         string   `json:"url,omitempty"`
	Interval    string   `json:"interval,omitempty"`
	Tolerance   int      `json:"tolerance,omitempty"`
	IdleTimeout string   `json:"idle_timeout,omitempty"`

	TLS       *tlsOptions `json:"tls,omitempty"`
	Transport *transport  `json:"transport,omitempty"`
	dial
}

// dial are the fields every outbound that dials has.
type dial struct {
	Detour        string `json:"detour,omitempty"`
	BindInterface string `json:"bind_interface,omitempty"`
	RoutingMark   int    `json:"routing_mark,omitempty"`
	TCPFastOpen   bool   `json:"tcp_fast_open,omitempty"`
	TCPMultiPath  bool   `json:"tcp_multi_path,omitempty"`
	// How the server's name is resolved: mihomo's ip-version.
	DomainResolver *domainResolver `json:"domain_resolver,omitempty"`
}

type domainResolver struct {
	Server   string `json:"server"`
	Strategy string `json:"strategy,omitempty"`
}

type udpOverTCP struct {
	Enabled bool `json:"enabled"`
	Version int  `json:"version,omitempty"`
}

type multiplex struct {
	Enabled        bool    `json:"enabled"`
	Protocol       string  `json:"protocol,omitempty"`
	MaxConnections int     `json:"max_connections,omitempty"`
	MinStreams     int     `json:"min_streams,omitempty"`
	MaxStreams     int     `json:"max_streams,omitempty"`
	Padding        bool    `json:"padding,omitempty"`
	Brutal         *brutal `json:"brutal,omitempty"`
}

type brutal struct {
	Enabled  bool `json:"enabled"`
	UpMbps   int  `json:"up_mbps,omitempty"`
	DownMbps int  `json:"down_mbps,omitempty"`
}

type obfs struct {
	Type          string `json:"type"`
	Password      string `json:"password"`
	MinPacketSize int    `json:"min_packet_size,omitempty"` // gecko
	MaxPacketSize int    `json:"max_packet_size,omitempty"`
}

type tlsOptions struct {
	Enabled    bool     `json:"enabled"`
	ServerName string   `json:"server_name,omitempty"`
	Insecure   bool     `json:"insecure,omitempty"`
	ALPN       []string `json:"alpn,omitempty"`
	// The two ways sing-box pins: the leaf's public key (base64
	// SHA-256), or the only roots trusted, as PEM lines.
	CertificatePublicKeySHA256 []string `json:"certificate_public_key_sha256,omitempty"`
	Certificate                []string `json:"certificate,omitempty"`
	// A client certificate, PEM lines or files.
	ClientCertificate     []string `json:"client_certificate,omitempty"`
	ClientCertificatePath []string `json:"client_certificate_path,omitempty"`
	ClientKey             []string `json:"client_key,omitempty"`
	ClientKeyPath         string   `json:"client_key_path,omitempty"`
	ECH                   *ech     `json:"ech,omitempty"`
	UTLS                  *utls    `json:"utls,omitempty"`
	Reality               *reality `json:"reality,omitempty"`
}

type ech struct {
	Enabled         bool     `json:"enabled"`
	Config          []string `json:"config,omitempty"` // PEM lines
	QueryServerName string   `json:"query_server_name,omitempty"`
}

type utls struct {
	Enabled     bool   `json:"enabled"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type reality struct {
	Enabled   bool   `json:"enabled"`
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id,omitempty"`
}

type transport struct {
	Type                string            `json:"type"`
	Host                any               `json:"host,omitempty"` // a list for http, a string for httpupgrade
	Path                string            `json:"path,omitempty"`
	Method              string            `json:"method,omitempty"` // http
	Headers             map[string]string `json:"headers,omitempty"`
	ServiceName         string            `json:"service_name,omitempty"`
	IdleTimeout         string            `json:"idle_timeout,omitempty"` // grpc: the ping interval
	MaxEarlyData        int               `json:"max_early_data,omitempty"`
	EarlyDataHeaderName string            `json:"early_data_header_name,omitempty"`
}

// endpoint is a WireGuard interface, which sing-box keeps apart from outbounds.
type endpoint struct {
	Type       string   `json:"type"`
	Tag        string   `json:"tag"`
	Address    []string `json:"address"`
	PrivateKey string   `json:"private_key"`
	MTU        int      `json:"mtu,omitempty"`
	Workers    int      `json:"workers,omitempty"`
	Peers      []wgPeer `json:"peers"`
	dial
}

type wgPeer struct {
	Address      string   `json:"address"`
	Port         int      `json:"port"`
	PublicKey    string   `json:"public_key"`
	PreSharedKey string   `json:"pre_shared_key,omitempty"`
	AllowedIPs   []string `json:"allowed_ips"`
	Reserved     []int    `json:"reserved,omitempty"`
	Keepalive    int      `json:"persistent_keepalive_interval,omitempty"`
}

type routing struct {
	Rules                 []rule    `json:"rules"`
	RuleSet               []ruleSet `json:"rule_set,omitempty"`
	Final                 string    `json:"final"`
	AutoDetectInterface   bool      `json:"auto_detect_interface,omitempty"`
	DefaultDomainResolver string    `json:"default_domain_resolver,omitempty"`
}

type rule struct {
	Inbound       []string `json:"inbound,omitempty"`
	Protocol      string   `json:"protocol,omitempty"`
	Domain        []string `json:"domain,omitempty"`
	DomainSuffix  []string `json:"domain_suffix,omitempty"`
	DomainKeyword []string `json:"domain_keyword,omitempty"`
	DomainRegex   []string `json:"domain_regex,omitempty"`
	IPCIDR        []string `json:"ip_cidr,omitempty"`
	Port          []int    `json:"port,omitempty"`
	PortRange     []string `json:"port_range,omitempty"`
	Network       []string `json:"network,omitempty"`
	ProcessName   []string `json:"process_name,omitempty"`
	ProcessPath   []string `json:"process_path,omitempty"`
	RuleSet       []string `json:"rule_set,omitempty"`
	Action        string   `json:"action,omitempty"`
	Outbound      string   `json:"outbound,omitempty"`
	Method        string   `json:"method,omitempty"` // reject
}

type ruleSet struct {
	Type           string     `json:"type"`
	Tag            string     `json:"tag"`
	Format         string     `json:"format"`
	URL            string     `json:"url"`
	HTTPClient     httpClient `json:"http_client"`
	UpdateInterval string     `json:"update_interval,omitempty"`
}

// httpClient downloads remote rule sets; with a detour, through the proxy.
type httpClient struct {
	Detour string `json:"detour,omitempty"`
}

type experimental struct {
	ClashAPI  *clashAPI  `json:"clash_api,omitempty"`
	CacheFile *cacheFile `json:"cache_file,omitempty"`
}

type clashAPI struct {
	ExternalController       string   `json:"external_controller"`
	Secret                   string   `json:"secret,omitempty"`
	AccessControlAllowOrigin []string `json:"access_control_allow_origin,omitempty"`
}

type cacheFile struct {
	Enabled     bool `json:"enabled"`
	StoreFakeIP bool `json:"store_fakeip,omitempty"`
}
