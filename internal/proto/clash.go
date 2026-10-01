package proto

import (
	"encoding/base64"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"nautilus/internal/model"
)

// FromClash decodes a mihomo/Clash proxy mapping. It never fails: fields it
// does not understand end up in Spec.Unknown, and unsupported protocols
// keep their type so backends can reject them by name.
func FromClash(m *yaml.Node) *Spec {
	r := newReader(m, "")
	s := &Spec{
		Type:   strings.ToLower(r.str("type")),
		Server: r.str("server"),
		Port:   r.int("port"),
		UDP:    r.bool("udp"),
		Sockopt: Sockopt{
			TFO:       r.bool("tfo"),
			MPTCP:     r.bool("mptcp"),
			Interface: r.str("interface-name"),
			Mark:      r.int("routing-mark"),
			IPVersion: strings.ToLower(r.str("ip-version")),
		},
	}
	r.ignore("name", "dialer-proxy")
	switch s.Type {
	case "ss":
		s.Cipher = r.str("cipher")
		s.Password = r.str("password")
		s.UDPOverTCP = r.bool("udp-over-tcp")
		r.ignore("udp-over-tcp-version")
		if p := r.str("plugin"); p != "" {
			r.ignore("plugin-opts")
			s.Unknown = append(s.Unknown, "plugin: "+p)
		}
	case "vmess":
		s.UUID = r.str("uuid")
		s.AlterID = r.int("alterId")
		s.Cipher = r.str("cipher")
		r.ignore("packet-encoding", "global-padding", "authenticated-length")
		readTLS(r, s, r.bool("tls"))
		readTransport(r, s)
	case "vless":
		s.UUID = r.str("uuid")
		s.Flow = r.str("flow")
		s.Encryption = r.str("encryption")
		r.ignore("packet-encoding", "xudp", "packet-addr")
		readTLS(r, s, r.bool("tls"))
		readTransport(r, s)
	case "trojan":
		s.Password = r.str("password")
		readTLS(r, s, true)
		readTransport(r, s)
		if o := r.sub("ss-opts"); o != nil && o.bool("enabled") {
			o.ignore("method", "password")
			s.Unknown = append(s.Unknown, "ss-opts")
		}
	case "socks5":
		s.Username = r.str("username")
		s.Password = r.str("password")
		readTLS(r, s, r.bool("tls"))
	case "http":
		s.Username = r.str("username")
		s.Password = r.str("password")
		s.Headers = r.strMap("headers")
		readTLS(r, s, r.bool("tls"))
	case "hysteria2":
		s.Password = r.str("password")
		s.UDP = true
		s.Hysteria = &Hysteria{
			Obfs:         r.str("obfs"),
			ObfsPassword: r.str("obfs-password"),
			Up:           bandwidth(r.str("up")),
			Down:         bandwidth(r.str("down")),
			Ports:        r.str("ports"),
			HopInterval:  r.int("hop-interval"),
		}
		readTLS(r, s, true)
	case "wireguard":
		s.UDP = true
		s.WireGuard = readWireGuard(r, s)
	default:
		// The protocol itself is what a backend will reject.
		r.ignoreAll()
	}
	s.Unknown = append(s.Unknown, r.unknown()...)
	slices.Sort(s.Unknown)
	return s
}

func readTLS(r *reader, s *Spec, enabled bool) {
	t := &TLS{
		SNI:         firstNonEmpty(r.str("servername"), r.str("sni")),
		ALPN:        r.strs("alpn"),
		Insecure:    r.bool("skip-cert-verify"),
		PinSHA256:   r.str("fingerprint"), // mihomo: server certificate sha256
		Fingerprint: r.str("client-fingerprint"),
	}
	if o := r.sub("reality-opts"); o != nil {
		t.Reality = &Reality{PublicKey: o.str("public-key"), ShortID: o.str("short-id"), SpiderX: o.str("spider-x")}
		enabled = true
	}
	if o := r.sub("ech-opts"); o != nil {
		if o.bool("enable") {
			s.Unknown = append(s.Unknown, "ech-opts")
		}
		o.ignoreAll()
	}
	if enabled {
		s.TLS = t
	}
}

func readTransport(r *reader, s *Spec) {
	t := Transport{Network: strings.ToLower(r.str("network"))}
	switch t.Network {
	case "", "tcp":
		t.Network = ""
	case "ws":
		if o := r.sub("ws-opts"); o != nil {
			t.Path = o.str("path")
			t.Headers = o.strMap("headers")
			t.EarlyData = o.int("max-early-data")
			t.EarlyDataHeader = o.str("early-data-header-name")
			if o.bool("v2ray-http-upgrade") {
				t.Network = "httpupgrade"
			}
			o.ignore("v2ray-http-upgrade-fast-open")
		}
	case "grpc":
		if o := r.sub("grpc-opts"); o != nil {
			t.ServiceName = o.str("grpc-service-name")
		}
	case "h2":
		if o := r.sub("h2-opts"); o != nil {
			t.Host = first(o.strs("host"))
			t.Path = o.str("path")
		}
	case "http":
		if o := r.sub("http-opts"); o != nil {
			t.Path = first(o.strs("path"))
			o.ignore("method", "headers")
		}
	case "xhttp":
		if o := r.sub("xhttp-opts"); o != nil {
			t.Path = o.str("path")
			t.Host = o.str("host")
			t.Mode = o.str("mode")
			t.Headers = o.strMap("headers")
		}
	}
	// Subscriptions often carry options for transports they do not use.
	r.ignore("ws-opts", "grpc-opts", "h2-opts", "http-opts", "xhttp-opts")
	// A Host header is the transport's host.
	for k, v := range t.Headers {
		if strings.EqualFold(k, "host") {
			if t.Host == "" {
				t.Host = v
			}
			delete(t.Headers, k)
		}
	}
	s.Transport = t
}

func readWireGuard(r *reader, s *Spec) *WireGuard {
	wg := &WireGuard{PrivateKey: r.str("private-key"), MTU: r.int("mtu")}
	if ip := r.str("ip"); ip != "" {
		wg.Address = append(wg.Address, withPrefix(ip))
	}
	if ip := r.str("ipv6"); ip != "" {
		wg.Address = append(wg.Address, withPrefix(ip))
	}
	peer := func(p *reader, server string, port int) WireGuardPeer {
		return WireGuardPeer{
			Server:       server,
			Port:         port,
			PublicKey:    p.str("public-key"),
			PreSharedKey: p.str("pre-shared-key"),
			Reserved:     reserved(p.node("reserved")),
			AllowedIPs:   p.strs("allowed-ips"),
		}
	}
	if peers := r.list("peers"); peers != nil {
		for _, p := range peers {
			wg.Peers = append(wg.Peers, peer(p, p.str("server"), p.int("port")))
		}
	} else {
		wg.Peers = append(wg.Peers, peer(r, s.Server, s.Port))
	}
	return wg
}

// bandwidth normalizes a Clash bandwidth: a bare number means Mbps.
func bandwidth(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return ""
	}
	if _, err := strconv.ParseFloat(v, 64); err == nil {
		return v + " mbps"
	}
	return v
}

// reserved accepts the WireGuard reserved bytes as a list or as base64.
func reserved(n *yaml.Node) []int {
	if n == nil {
		return nil
	}
	var out []int
	if n.Kind == yaml.SequenceNode {
		for _, c := range n.Content {
			if v, ok := model.WeakInt(c); ok {
				out = append(out, v)
			}
		}
		return out
	}
	s := model.WeakString(n)
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		for _, c := range b {
			out = append(out, int(c))
		}
		return out
	}
	for f := range strings.SplitSeq(s, ",") {
		if v, err := strconv.Atoi(strings.TrimSpace(f)); err == nil {
			out = append(out, v)
		}
	}
	return out
}

func withPrefix(ip string) string {
	if strings.Contains(ip, "/") {
		return ip
	}
	if a, err := netip.ParseAddr(ip); err == nil {
		return netip.PrefixFrom(a, a.BitLen()).String()
	}
	return ip
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

func first(vs []string) string {
	if len(vs) == 0 {
		return ""
	}
	return vs[0]
}

// reader reads a mapping leniently and remembers which keys were used, so
// leftovers can be reported.
type reader struct {
	m        *yaml.Node
	prefix   string
	used     map[string]bool
	all      bool
	children []*reader
}

func newReader(m *yaml.Node, prefix string) *reader {
	return &reader{m: m, prefix: prefix, used: map[string]bool{}}
}

func (r *reader) node(key string) *yaml.Node {
	r.used[model.NormKey(key)] = true
	return model.Lookup(r.m, key)
}

func (r *reader) str(key string) string { return model.WeakString(r.node(key)) }

func (r *reader) int(key string) int {
	v, _ := model.WeakInt(r.node(key))
	return v
}

func (r *reader) bool(key string) bool {
	v, _ := model.WeakBool(r.node(key))
	return v
}

// strs accepts a list or a comma-separated string.
func (r *reader) strs(key string) []string {
	n := r.node(key)
	if n == nil {
		return nil
	}
	var out []string
	if n.Kind == yaml.SequenceNode {
		for _, c := range n.Content {
			if v := model.WeakString(c); v != "" {
				out = append(out, v)
			}
		}
		return out
	}
	for f := range strings.SplitSeq(model.WeakString(n), ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func (r *reader) strMap(key string) map[string]string {
	n := r.node(key)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	out := map[string]string{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		out[n.Content[i].Value] = model.WeakString(n.Content[i+1])
	}
	return out
}

func (r *reader) sub(key string) *reader {
	n := r.node(key)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	c := newReader(n, r.prefix+key+".")
	r.children = append(r.children, c)
	return c
}

func (r *reader) list(key string) []*reader {
	n := r.node(key)
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	var out []*reader
	for i, item := range n.Content {
		if item.Kind == yaml.MappingNode {
			c := newReader(item, r.prefix+key+"["+strconv.Itoa(i)+"].")
			r.children = append(r.children, c)
			out = append(out, c)
		}
	}
	return out
}

func (r *reader) ignore(keys ...string) {
	for _, k := range keys {
		r.used[model.NormKey(k)] = true
	}
}

func (r *reader) ignoreAll() { r.all = true }

func (r *reader) unknown() []string {
	var out []string
	if !r.all {
		for i := 0; i+1 < len(r.m.Content); i += 2 {
			if k := r.m.Content[i].Value; !r.used[model.NormKey(k)] {
				out = append(out, r.prefix+k)
			}
		}
	}
	for _, c := range r.children {
		out = append(out, c.unknown()...)
	}
	return out
}
