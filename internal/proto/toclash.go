package proto

import (
	"cmp"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"nautilus/internal/model"
)

// ToClash encodes a Spec as a mihomo/Clash proxy mapping. It is the inverse
// of FromClash for every field a Spec can hold, so nodes from share links
// can flow through the same pipeline as nodes written in Clash format.
func ToClash(name string, s *Spec) *yaml.Node {
	m := &mapping{n: &yaml.Node{Kind: yaml.MappingNode}}
	m.str("name", name)
	m.str("type", s.Type)
	m.str("server", s.Server)
	m.int("port", s.Port)
	if s.UDP && s.Type != "hysteria2" && s.Type != "wireguard" {
		m.bool("udp", true)
	}
	switch s.Type {
	case "ss":
		m.str("cipher", s.Cipher)
		m.str("password", s.Password)
		if s.UDPOverTCP {
			m.bool("udp-over-tcp", true)
		}
	case "vmess":
		m.str("uuid", s.UUID)
		m.int("alterId", s.AlterID)
		m.str("cipher", cmp.Or(s.Cipher, "auto"))
		tlsClash(m, s.TLS, true, "servername")
		transportClash(m, s.Transport)
	case "vless":
		m.str("uuid", s.UUID)
		m.str("flow", s.Flow)
		if s.Encryption != "" && s.Encryption != "none" {
			m.str("encryption", s.Encryption)
		}
		tlsClash(m, s.TLS, true, "servername")
		transportClash(m, s.Transport)
	case "trojan":
		m.str("password", s.Password)
		tlsClash(m, s.TLS, false, "sni")
		transportClash(m, s.Transport)
	case "socks5", "http":
		m.str("username", s.Username)
		m.str("password", s.Password)
		if len(s.Headers) > 0 {
			m.strMap("headers", s.Headers)
		}
		tlsClash(m, s.TLS, true, "sni")
	case "hysteria2":
		m.str("password", s.Password)
		if h := s.Hysteria; h != nil {
			m.str("obfs", h.Obfs)
			m.str("obfs-password", h.ObfsPassword)
			m.str("up", clashBandwidth(h.Up))
			m.str("down", clashBandwidth(h.Down))
			m.str("ports", h.Ports)
			if h.HopInterval > 0 {
				m.int("hop-interval", h.HopInterval)
			}
		}
		tlsClash(m, s.TLS, false, "sni")
	case "wireguard":
		wireguardClash(m, s.WireGuard)
	}
	o := s.Sockopt
	if o.TFO {
		m.bool("tfo", true)
	}
	if o.MPTCP {
		m.bool("mptcp", true)
	}
	m.str("interface-name", o.Interface)
	if o.Mark != 0 {
		m.int("routing-mark", o.Mark)
	}
	m.str("ip-version", o.IPVersion)
	return m.n
}

// tlsClash writes TLS options. Protocols where TLS is optional carry an
// explicit "tls: true"; sniKey is the field name that protocol uses.
func tlsClash(m *mapping, t *TLS, explicit bool, sniKey string) {
	if t == nil {
		return
	}
	if explicit {
		m.bool("tls", true)
	}
	m.str(sniKey, t.SNI)
	if len(t.ALPN) > 0 {
		m.strs("alpn", t.ALPN)
	}
	if t.Insecure {
		m.bool("skip-cert-verify", true)
	}
	m.str("fingerprint", t.PinSHA256)
	m.str("client-fingerprint", t.Fingerprint)
	if r := t.Reality; r != nil {
		ro := &mapping{n: &yaml.Node{Kind: yaml.MappingNode}}
		ro.str("public-key", r.PublicKey)
		ro.str("short-id", r.ShortID)
		ro.str("spider-x", r.SpiderX)
		m.node("reality-opts", ro.n)
	}
}

func transportClash(m *mapping, t Transport) {
	headers := map[string]string{}
	for k, v := range t.Headers {
		headers[k] = v
	}
	if t.Host != "" {
		headers["Host"] = t.Host
	}
	o := &mapping{n: &yaml.Node{Kind: yaml.MappingNode}}
	switch t.Network {
	case "":
		return
	case "ws", "httpupgrade":
		m.str("network", "ws")
		o.str("path", t.Path)
		if len(headers) > 0 {
			o.strMap("headers", headers)
		}
		if t.EarlyData > 0 {
			o.int("max-early-data", t.EarlyData)
			o.str("early-data-header-name", t.EarlyDataHeader)
		}
		if t.Network == "httpupgrade" {
			o.bool("v2ray-http-upgrade", true)
		}
		m.node("ws-opts", o.n)
	case "grpc":
		m.str("network", "grpc")
		o.str("grpc-service-name", t.ServiceName)
		m.node("grpc-opts", o.n)
	case "h2":
		m.str("network", "h2")
		if t.Host != "" {
			o.strs("host", []string{t.Host})
		}
		o.str("path", t.Path)
		m.node("h2-opts", o.n)
	case "http":
		m.str("network", "http")
		if t.Path != "" {
			o.strs("path", []string{t.Path})
		}
		m.node("http-opts", o.n)
	case "xhttp":
		m.str("network", "xhttp")
		o.str("path", t.Path)
		o.str("host", t.Host)
		o.str("mode", t.Mode)
		if len(t.Headers) > 0 {
			o.strMap("headers", t.Headers)
		}
		m.node("xhttp-opts", o.n)
	default:
		m.str("network", t.Network)
	}
}

func wireguardClash(m *mapping, w *WireGuard) {
	if w == nil {
		return
	}
	m.str("private-key", w.PrivateKey)
	for _, a := range w.Address {
		key := "ip"
		if p, err := netip.ParsePrefix(a); err == nil {
			if p.Addr().Is6() {
				key = "ipv6"
			}
			if p.Bits() == p.Addr().BitLen() {
				a = p.Addr().String()
			}
		}
		m.str(key, a)
	}
	if w.MTU > 0 {
		m.int("mtu", w.MTU)
	}
	peer := func(pm *mapping, p WireGuardPeer) {
		pm.str("public-key", p.PublicKey)
		pm.str("pre-shared-key", p.PreSharedKey)
		if len(p.Reserved) > 0 {
			pm.ints("reserved", p.Reserved)
		}
		if len(p.AllowedIPs) > 0 {
			pm.strs("allowed-ips", p.AllowedIPs)
		}
	}
	if len(w.Peers) == 1 {
		peer(m, w.Peers[0])
		return
	}
	seq := &yaml.Node{Kind: yaml.SequenceNode}
	for _, p := range w.Peers {
		pm := &mapping{n: &yaml.Node{Kind: yaml.MappingNode}}
		pm.str("server", p.Server)
		pm.int("port", p.Port)
		peer(pm, p)
		seq.Content = append(seq.Content, pm.n)
	}
	m.node("peers", seq)
}

// clashBandwidth writes a normalized bandwidth the way mihomo parses it:
// "50 mbps" becomes "50 Mbps".
func clashBandwidth(v string) string {
	num, unit, ok := strings.Cut(v, " ")
	if !ok {
		return v
	}
	if u := strings.TrimSuffix(unit, "bps"); u != unit && len(u) == 1 {
		return num + " " + strings.ToUpper(u) + "bps"
	}
	return v
}

// mapping builds a YAML mapping, skipping empty strings.
type mapping struct{ n *yaml.Node }

func (m *mapping) node(key string, v *yaml.Node) {
	m.n.Content = append(m.n.Content, model.Str(key), v)
}

func (m *mapping) str(key, v string) {
	if v != "" {
		m.node(key, model.Str(v))
	}
}

func (m *mapping) int(key string, v int) {
	m.node(key, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(v)})
}

func (m *mapping) bool(key string, v bool) {
	m.node(key, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: strconv.FormatBool(v)})
}

func (m *mapping) strs(key string, vs []string) {
	seq := &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle}
	for _, v := range vs {
		seq.Content = append(seq.Content, model.Str(v))
	}
	m.node(key, seq)
}

func (m *mapping) ints(key string, vs []int) {
	seq := &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle}
	for _, v := range vs {
		seq.Content = append(seq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(v)})
	}
	m.node(key, seq)
}

func (m *mapping) strMap(key string, kv map[string]string) {
	sub := &yaml.Node{Kind: yaml.MappingNode}
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		sub.Content = append(sub.Content, model.Str(k), model.Str(kv[k]))
	}
	m.node(key, sub)
}
