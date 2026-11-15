// Package nodeform describes the form nodes are written in by hand, for
// the Web UI and the TUI alike, and moves nodes between the form, a
// profile's YAML and JSON.
//
// A node is the mapping profile.yaml has, in Clash's words (which mihomo
// reads as they are): the form edits that mapping in place, so whatever
// it has no input for is kept.
package nodeform

// Option is one choice of a select.
type Option struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// Field is one input. Key is a path into the node's mapping, with dots
// for nested mappings ("ws-opts.path").
type Field struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	// Kind is text, secret, number, bool, select, or list (comma separated).
	Kind    string   `json:"kind"`
	Options []Option `json:"options,omitempty"`
	Hint    string   `json:"hint,omitempty"`
	// Types are the protocols the field belongs to; none means all.
	Types []string `json:"types,omitempty"`
	// When holds values other fields must have for this one to show,
	// "true" for a bool that is on.
	When map[string][]string `json:"when,omitempty"`
	// More fields are folded away until asked for.
	More     bool `json:"more,omitempty"`
	Required bool `json:"required,omitempty"`
	// Default is what a new node of the type starts with.
	Default any `json:"default,omitempty"`
}

// Types are the protocols the form offers; others go in as YAML.
var Types = []Option{
	{"ss", "Shadowsocks"}, {"vmess", "VMess"}, {"vless", "VLESS"}, {"trojan", "Trojan"},
	{"hysteria2", "Hysteria 2"}, {"socks5", "SOCKS5"}, {"http", "HTTP"}, {"wireguard", "WireGuard"},
}

var (
	tlsOptional = []string{"vmess", "vless", "socks5", "http"}
	streams     = []string{"vmess", "vless", "trojan"} // what has transports
	withTLS     = map[string][]string{"tls": {"true"}}
)

// tlsOn shows a field when the node has TLS: always for trojan and
// hysteria2, when tls is on for the others.
func tlsOn(types ...string) (t []string, when map[string][]string) {
	for _, x := range types {
		for _, y := range tlsOptional {
			if x == y {
				return types, withTLS
			}
		}
	}
	return types, nil
}

// Fields are the form's inputs in the order they show and nodes are
// written in.
var Fields = func() []Field {
	f := []Field{
		{Key: "name", Label: "名字", Kind: "text", Required: true},
		{Key: "type", Label: "协议", Kind: "select", Options: Types, Required: true},
		{Key: "server", Label: "服务器", Kind: "text", Hint: "域名或 IP", Required: true},
		{Key: "port", Label: "端口", Kind: "number", Required: true},

		{Key: "cipher", Label: "加密方式", Kind: "select", Types: []string{"ss"}, Default: "aes-128-gcm", Options: opts(
			"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
			"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305")},
		{Key: "cipher", Label: "加密方式", Kind: "select", Types: []string{"vmess"}, Default: "auto", Options: opts("auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero")},
		{Key: "uuid", Label: "UUID", Kind: "text", Types: []string{"vmess", "vless"}, Required: true},
		{Key: "alterId", Label: "alterId", Kind: "number", Types: []string{"vmess"}, More: true, Hint: "0"},
		{Key: "flow", Label: "流控", Kind: "select", Types: []string{"vless"}, Options: []Option{{"", "不用"}, {"xtls-rprx-vision", "xtls-rprx-vision"}}},
		{Key: "encryption", Label: "VLESS 加密", Kind: "text", Types: []string{"vless"}, More: true, Hint: "none"},
		{Key: "username", Label: "用户名", Kind: "text", Types: []string{"socks5", "http"}},
		{Key: "password", Label: "密码", Kind: "secret", Types: []string{"ss", "trojan", "hysteria2", "socks5", "http"}},

		{Key: "private-key", Label: "私钥", Kind: "secret", Types: []string{"wireguard"}, Required: true},
		{Key: "public-key", Label: "对端公钥", Kind: "text", Types: []string{"wireguard"}, Required: true},
		{Key: "ip", Label: "本机 IPv4", Kind: "text", Types: []string{"wireguard"}, Hint: "172.16.0.2"},
		{Key: "ipv6", Label: "本机 IPv6", Kind: "text", Types: []string{"wireguard"}, More: true},
		{Key: "pre-shared-key", Label: "预共享密钥", Kind: "secret", Types: []string{"wireguard"}, More: true},
		{Key: "allowed-ips", Label: "允许的 IP", Kind: "list", Types: []string{"wireguard"}, More: true, Hint: "0.0.0.0/0, ::/0"},
		{Key: "reserved", Label: "reserved", Kind: "list", Types: []string{"wireguard"}, More: true, Hint: "1, 2, 3"},
		{Key: "mtu", Label: "MTU", Kind: "number", Types: []string{"wireguard"}, More: true},

		{Key: "obfs", Label: "混淆", Kind: "select", Types: []string{"hysteria2"}, Options: []Option{{"", "不用"}, {"salamander", "salamander"}, {"gecko", "gecko"}}},
		{Key: "obfs-password", Label: "混淆密码", Kind: "secret", Types: []string{"hysteria2"}, When: map[string][]string{"obfs": {"salamander", "gecko"}}},
		{Key: "obfs-min-packet-size", Label: "最小包", Kind: "number", Types: []string{"hysteria2"}, When: map[string][]string{"obfs": {"gecko"}}, More: true, Hint: "512"},
		{Key: "obfs-max-packet-size", Label: "最大包", Kind: "number", Types: []string{"hysteria2"}, When: map[string][]string{"obfs": {"gecko"}}, More: true, Hint: "1200"},
		{Key: "ports", Label: "端口跳跃", Kind: "text", Types: []string{"hysteria2"}, More: true, Hint: "443,20000-30000"},
		{Key: "hop-interval", Label: "跳跃间隔（秒）", Kind: "text", Types: []string{"hysteria2"}, More: true, Hint: "30，或 10-30 随机"},
		{Key: "up", Label: "上行带宽", Kind: "text", Types: []string{"hysteria2"}, More: true, Hint: "50 Mbps"},
		{Key: "down", Label: "下行带宽", Kind: "text", Types: []string{"hysteria2"}, More: true, Hint: "200 Mbps"},

		{Key: "tls", Label: "TLS", Kind: "bool", Types: tlsOptional},
	}
	tls := func(field Field, types ...string) Field {
		field.Types, field.When = tlsOn(types...)
		return field
	}
	f = append(f,
		tls(Field{Key: "servername", Label: "SNI", Kind: "text", Hint: "证书上的域名"}, "vmess", "vless"),
		tls(Field{Key: "sni", Label: "SNI", Kind: "text", Hint: "证书上的域名"}, "trojan", "hysteria2", "http"),
		tls(Field{Key: "reality-opts.public-key", Label: "REALITY 公钥", Kind: "text", Hint: "用 REALITY 时填"}, "vless"),
		tls(Field{Key: "reality-opts.short-id", Label: "REALITY short ID", Kind: "text"}, "vless"),
		tls(Field{Key: "skip-cert-verify", Label: "跳过证书校验", Kind: "bool"}, "vmess", "vless", "trojan", "hysteria2", "socks5", "http"),
		tls(Field{Key: "fingerprint", Label: "证书指纹", Kind: "text", Hint: "证书的 SHA256，自签证书用", More: true}, "vmess", "vless", "trojan", "hysteria2", "socks5", "http"),
		tls(Field{Key: "client-fingerprint", Label: "uTLS 指纹", Kind: "select", More: true,
			Options: append([]Option{{"", "不用"}}, opts("chrome", "firefox", "safari", "ios", "edge", "random")...)}, "vmess", "vless", "trojan"),
		tls(Field{Key: "alpn", Label: "ALPN", Kind: "list", Hint: "h2, http/1.1", More: true}, "vmess", "vless", "trojan", "hysteria2"),

		Field{Key: "network", Label: "传输方式", Kind: "select", Types: streams,
			Options: []Option{{"", "TCP"}, {"ws", "WebSocket"}, {"grpc", "gRPC"}, {"h2", "HTTP/2"}, {"http", "HTTP"}, {"xhttp", "XHTTP"}}},
		onNetwork("ws", Field{Key: "ws-opts.path", Label: "路径", Kind: "text", Hint: "/"}),
		onNetwork("ws", Field{Key: "ws-opts.headers.Host", Label: "Host", Kind: "text"}),
		onNetwork("grpc", Field{Key: "grpc-opts.grpc-service-name", Label: "服务名", Kind: "text"}),
		onNetwork("h2", Field{Key: "h2-opts.path", Label: "路径", Kind: "text"}),
		onNetwork("h2", Field{Key: "h2-opts.host", Label: "Host", Kind: "list"}),
		onNetwork("http", Field{Key: "http-opts.path", Label: "路径", Kind: "list"}),
		onNetwork("xhttp", Field{Key: "xhttp-opts.path", Label: "路径", Kind: "text"}),
		onNetwork("xhttp", Field{Key: "xhttp-opts.host", Label: "Host", Kind: "text"}),
		onNetwork("xhttp", Field{Key: "xhttp-opts.mode", Label: "模式", Kind: "select", Options: append([]Option{{"", "自动"}}, opts("packet-up", "stream-up", "stream-one")...)}),

		Field{Key: "udp", Label: "UDP", Kind: "bool", Types: []string{"ss", "vmess", "vless", "trojan", "socks5"}, Default: true},
		Field{Key: "udp-over-tcp", Label: "UDP over TCP", Kind: "bool", Types: []string{"ss"}, More: true},
	)
	return f
}()

func opts(values ...string) []Option {
	out := make([]Option, len(values))
	for i, v := range values {
		out[i] = Option{v, v}
	}
	return out
}

func onNetwork(network string, f Field) Field {
	f.Types, f.When = streams, map[string][]string{"network": {network}}
	return f
}

// Form is everything a UI needs to draw the form.
type Form struct {
	Types  []Option `json:"types"`
	Fields []Field  `json:"fields"`
}

// Schema is the form as the API serves it.
func Schema() Form { return Form{Types: Types, Fields: Fields} }
