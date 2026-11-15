package proto

import (
	"cmp"
	"encoding/base64"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/xiongnemo/conch/internal/model"
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
		if s.UDPOverTCP {
			s.UoTVersion = cmpInt(r.int("udp-over-tcp-version"), 1) // mihomo's default
		} else {
			r.ignore("udp-over-tcp-version")
		}
		s.Mux = readMux(r)
		s.Plugin = readPlugin(r, s)
		r.ignore("client-fingerprint") // only plugins use it
	case "vmess":
		s.UUID = r.str("uuid")
		s.AlterID = r.int("alterId")
		s.Cipher = r.str("cipher")
		s.GlobalPadding = r.bool("global-padding")
		s.AuthenticatedLength = r.bool("authenticated-length")
		s.PacketEncoding = packetEncoding(r)
		s.Mux = readMux(r)
		readTLS(r, s, r.bool("tls"))
		readTransport(r, s)
	case "vless":
		s.UUID = r.str("uuid")
		s.Flow = r.str("flow")
		s.Encryption = r.str("encryption")
		s.PacketEncoding = packetEncoding(r)
		s.Mux = readMux(r)
		readTLS(r, s, r.bool("tls"))
		readTransport(r, s)
	case "trojan":
		s.Password = r.str("password")
		s.Mux = readMux(r)
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
			Obfs:             r.str("obfs"),
			ObfsPassword:     r.str("obfs-password"),
			Ports:            HopPorts(r.str("ports")),
			ObfsMinPacket:    r.int("obfs-min-packet-size"),
			ObfsMaxPacket:    r.int("obfs-max-packet-size"),
			BBRProfile:       r.str("bbr-profile"),
			InitStreamWindow: uint64(r.int("initial-stream-receive-window")),
			MaxStreamWindow:  uint64(r.int("max-stream-receive-window")),
			InitConnWindow:   uint64(r.int("initial-connection-receive-window")),
			MaxConnWindow:    uint64(r.int("max-connection-receive-window")),
		}
		if v := r.str("hop-interval"); v != "" {
			lo, hi, ok := IntRange(v)
			if !ok {
				s.Unknown = append(s.Unknown, "hop-interval: "+v)
			}
			s.Hysteria.HopMin, s.Hysteria.HopMax = lo, hi
		}
		s.Hysteria.Up, s.Hysteria.Down = bandwidths(s, r.str("up"), r.str("down"))
		// mihomo's hysteria2 has no uTLS or REALITY and ignores their keys.
		r.ignore("client-fingerprint", "reality-opts")
		readQUICTLS(r, s)
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
	t := readTLSCommon(r, s)
	t.Fingerprint = r.str("client-fingerprint")
	// REALITY is a kind of TLS: mihomo ignores its options without tls.
	if o := r.sub("reality-opts"); o != nil {
		t.Reality = &Reality{PublicKey: o.str("public-key"), ShortID: o.str("short-id"), SpiderX: o.str("spider-x")}
	}
	if enabled {
		s.TLS = t
	}
}

// readQUICTLS reads the TLS of a QUIC protocol, which is always on.
func readQUICTLS(r *reader, s *Spec) {
	s.TLS = readTLSCommon(r, s)
}

func readTLSCommon(r *reader, s *Spec) *TLS {
	t := &TLS{
		SNI:       firstNonEmpty(r.str("servername"), r.str("sni")),
		ALPN:      r.strs("alpn"),
		Insecure:  r.bool("skip-cert-verify"),
		PinSHA256: r.str("fingerprint"), // mihomo: server certificate sha256
	}
	t.VerifyName = r.str("name-cert-verify")
	t.Certificate, t.PrivateKey = r.str("certificate"), r.str("private-key")
	if o := r.sub("ech-opts"); o != nil {
		if o.bool("enable") {
			t.ECH = &ECH{Config: o.str("config"), QueryServerName: o.str("query-server-name")}
		} else {
			o.ignoreAll()
		}
	}
	return t
}

// readMux reads sing-mux options (smux), when they are on.
func readMux(r *reader) *Mux {
	o := r.sub("smux")
	if o == nil {
		return nil
	}
	if !o.bool("enabled") {
		o.ignoreAll()
		return nil
	}
	m := &Mux{Protocol: o.str("protocol"), MaxConnections: o.int("max-connections"), MinStreams: o.int("min-streams"),
		MaxStreams: o.int("max-streams"), Padding: o.bool("padding")}
	if b := o.sub("brutal-opts"); b != nil {
		if b.bool("enabled") {
			m.BrutalUp, _ = ParseBandwidth(b.str("up"))
			m.BrutalDown, _ = ParseBandwidth(b.str("down"))
		} else {
			b.ignoreAll()
		}
	}
	return m
}

// packetEncoding is how VMess and VLESS carry UDP: packet-encoding, or
// the older xudp and packet-addr switches.
func packetEncoding(r *reader) string {
	switch {
	case r.str("packet-encoding") != "":
		r.ignore("xudp", "packet-addr")
		return r.str("packet-encoding")
	case r.bool("packet-addr"):
		r.ignore("xudp")
		return "packetaddr"
	case r.bool("xudp"):
		return "xudp"
	}
	return ""
}

func cmpInt(a, b int) int {
	if a != 0 {
		return a
	}
	return b
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
			t.UserAgent = o.str("grpc-user-agent")
			t.PingInterval = o.int("ping-interval")
		}
	case "h2":
		if o := r.sub("h2-opts"); o != nil {
			t.Hosts = o.strs("host")
			t.Host = first(t.Hosts)
			t.Path = o.str("path")
		}
	case "http":
		if o := r.sub("http-opts"); o != nil {
			t.Method = o.str("method")
			t.Paths = o.strs("path")
			t.Path = first(t.Paths)
			// Headers are lists here; Host is the transport's hosts.
			if h := o.sub("headers"); h != nil {
				for i := 0; i+1 < len(h.m.Content); i += 2 {
					k := h.m.Content[i].Value
					vals := h.strs(k)
					if strings.EqualFold(k, "host") {
						t.Hosts = vals
						t.Host = first(vals)
						continue
					}
					if len(vals) > 0 {
						if t.Headers == nil {
							t.Headers = map[string]string{}
						}
						t.Headers[k] = vals[0]
					}
				}
			}
		}
	case "xhttp":
		if o := r.sub("xhttp-opts"); o != nil {
			t.Path = o.str("path")
			t.Host = o.str("host")
			t.Mode = o.str("mode")
			t.Headers = o.strMap("headers")
			t.XHTTPExtra = rawKeys(o, XHTTPKeys)
			if d := o.sub("download-settings"); d != nil {
				t.Download = readDownload(d, s)
			}
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
	if len(t.Headers) == 0 {
		t.Headers = nil
	}
	s.Transport = t
}

func readWireGuard(r *reader, s *Spec) *WireGuard {
	wg := &WireGuard{PrivateKey: r.str("private-key"), MTU: r.int("mtu"), Keepalive: r.int("persistent-keepalive"), Workers: r.int("workers")}
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
// bandwidths reads up and down; what cannot be read is reported.
func bandwidths(s *Spec, up, down string) (uint64, uint64) {
	read := func(key, v string) uint64 {
		bits, ok := ParseBandwidth(v)
		if !ok && strings.TrimSpace(v) != "" {
			s.Unknown = append(s.Unknown, fmt.Sprintf("%s: %s（看不懂的带宽）", key, v))
		}
		return bits
	}
	return read("up", up), read("down", down)
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

// HopPorts writes hopping ports the one way backends read them: mihomo
// also separates them with "/".
func HopPorts(ports string) string {
	return strings.ReplaceAll(strings.TrimSpace(ports), "/", ",")
}

// IntRange reads "10" or "10-30".
func IntRange(v string) (lo, hi int, ok bool) {
	a, b, isRange := strings.Cut(strings.TrimSpace(v), "-")
	lo, err := strconv.Atoi(strings.TrimSpace(a))
	if err != nil || lo < 0 {
		return 0, 0, false
	}
	hi = lo
	if isRange {
		if hi, err = strconv.Atoi(strings.TrimSpace(b)); err != nil || hi < lo {
			return 0, 0, false
		}
	}
	return lo, hi, true
}

// readPlugin reads a shadowsocks plugin and its options with mihomo's
// defaults. Of plugins only mihomo has there is just the name, for other
// kernels to refuse: without its plugin a node does not connect.
func readPlugin(r *reader, s *Spec) *Plugin {
	name := r.str("plugin")
	if name == "" {
		r.ignore("plugin-opts")
		return nil
	}
	o := r.sub("plugin-opts")
	if o == nil {
		o = newReader(&yaml.Node{Kind: yaml.MappingNode}, "plugin-opts.")
	}
	p := &Plugin{Name: name, Mode: o.str("mode"), Host: cmp.Or(o.str("host"), "bing.com")}
	tlsOf := func() *TLS {
		return &TLS{SNI: p.Host, Insecure: o.bool("skip-cert-verify"), PinSHA256: o.str("fingerprint"), VerifyName: o.str("name-cert-verify"),
			Certificate: o.str("certificate"), PrivateKey: o.str("private-key")}
	}
	switch name {
	case "obfs":
	case "v2ray-plugin", "gost-plugin":
		p.Path, p.Headers = o.str("path"), o.strMap("headers")
		p.Mux = true
		if v, ok := model.WeakBool(o.node("mux")); ok {
			p.Mux = v
		}
		if name == "v2ray-plugin" {
			p.HTTPUpgrade = o.bool("v2ray-http-upgrade")
			o.ignore("v2ray-http-upgrade-fast-open")
		}
		if o.bool("tls") {
			p.TLS = tlsOf()
			if e := o.sub("ech-opts"); e != nil {
				if e.bool("enable") {
					p.TLS.ECH = &ECH{Config: e.str("config"), QueryServerName: e.str("query-server-name")}
				} else {
					e.ignoreAll()
				}
			}
		}
	case "shadow-tls":
		p.Password, p.Version = o.str("password"), cmpInt(o.int("version"), 2)
		p.TLS = tlsOf()
		p.TLS.ALPN = o.strs("alpn")
		if p.TLS.ALPN == nil {
			p.TLS.ALPN = []string{"h2", "http/1.1"}
		}
		// The node's client-fingerprint is shadow-tls's, in mihomo.
		p.TLS.Fingerprint = r.str("client-fingerprint")
	default:
		o.ignoreAll()
		return &Plugin{Name: name}
	}
	return p
}

// rawKeys takes the keys of a mapping that known has, as written.
func rawKeys(o *reader, known map[string]string) map[string]any {
	var out map[string]any
	for i := 0; i+1 < len(o.m.Content); i += 2 {
		k := o.m.Content[i].Value
		if _, ok := known[k]; !ok {
			continue
		}
		var v any
		if o.node(k).Decode(&v) == nil {
			if out == nil {
				out = map[string]any{}
			}
			out[k] = v
		}
	}
	return out
}

// readDownload reads XHTTP's download-settings, inheriting what it does
// not say from the node, as mihomo does.
func readDownload(d *reader, s *Spec) *XHTTPDownload {
	dl := &XHTTPDownload{Server: cmp.Or(d.str("server"), s.Server), Port: cmpInt(d.int("port"), s.Port),
		Path: d.str("path"), Host: d.str("host"), Headers: d.strMap("headers"), Extra: rawKeys(d, map[string]string{"reuse-settings": ""})}
	tlsOn := s.TLS != nil
	if v, ok := model.WeakBool(d.node("tls")); ok {
		tlsOn = v
	}
	if !tlsOn {
		d.ignore("alpn", "servername", "skip-cert-verify", "fingerprint", "client-fingerprint", "name-cert-verify", "certificate", "private-key", "ech-opts", "reality-opts")
		return dl
	}
	t := &TLS{}
	if s.TLS != nil {
		c := *s.TLS
		t = &c
	}
	if v := d.strs("alpn"); v != nil {
		t.ALPN = v
	}
	if v := d.str("servername"); v != "" {
		t.SNI = v
	}
	if v, ok := model.WeakBool(d.node("skip-cert-verify")); ok {
		t.Insecure = v
	}
	for key, to := range map[string]*string{"fingerprint": &t.PinSHA256, "client-fingerprint": &t.Fingerprint,
		"name-cert-verify": &t.VerifyName, "certificate": &t.Certificate, "private-key": &t.PrivateKey} {
		if v := d.str(key); v != "" {
			*to = v
		}
	}
	if o := d.sub("ech-opts"); o != nil {
		t.ECH = nil
		if o.bool("enable") {
			t.ECH = &ECH{Config: o.str("config"), QueryServerName: o.str("query-server-name")}
		} else {
			o.ignoreAll()
		}
	}
	if o := d.sub("reality-opts"); o != nil {
		t.Reality = &Reality{PublicKey: o.str("public-key"), ShortID: o.str("short-id"), SpiderX: o.str("spider-x")}
	}
	dl.TLS = t
	return dl
}
