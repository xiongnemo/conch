package singbox

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/xiongnemo/conch/internal/certpin"
	"github.com/xiongnemo/conch/internal/compile"
	"github.com/xiongnemo/conch/internal/proto"
)

// Shadowsocks methods sing-box implements.
var ssMethods = []string{
	"none", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
	"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
	"aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "rc4-md5", "chacha20-ietf", "xchacha20",
}

// uTLS fingerprints sing-box accepts.
var fingerprints = []string{"chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android", "random", "randomized"}

// fingerprint is mihomo's client-fingerprint in sing-box's names; ""
// means no uTLS, as "none" and names mihomo does not know do in mihomo.
func fingerprint(name string) (string, []string) {
	name = strings.ToLower(name)
	switch {
	case name == "" || name == "none" || slices.Contains(fingerprints, name):
		if name == "none" {
			name = ""
		}
		return name, nil
	case name == "chrome120" || strings.HasPrefix(name, "chrome_"):
		return "chrome", []string{fmt.Sprintf("sing-box 没有 %s 指纹，改用 chrome", name)}
	case name == "firefox120":
		return "firefox", []string{"sing-box 没有 firefox120 指纹，改用 firefox"}
	case name == "safari16":
		return "safari", []string{"sing-box 没有 safari16 指纹，改用 safari"}
	}
	return "", []string{fmt.Sprintf("mihomo 不认识 uTLS 指纹 %q，不会用 uTLS；sing-box 也不用", name)}
}

// ipStrategy is mihomo's ip-version as sing-box's resolve strategy.
var ipStrategy = map[string]string{"ipv4": "ipv4_only", "ipv6": "ipv6_only", "ipv4-prefer": "prefer_ipv4", "ipv6-prefer": "prefer_ipv6"}

// nodeOutbound translates one proxy. WireGuard nodes become endpoints.
// Problems that make the node unusable are errors; lossy translations
// are reported as warnings.
func (e *encoder) nodeOutbound(p *compile.Proxy) (*outbound, *endpoint, []string, error) {
	s := proto.FromClash(p.Node.Raw)
	s.Resolve()
	o := &outbound{Tag: p.Name, Server: s.Server, ServerPort: s.Port}
	var warns []string
	switch s.Type {
	case "ss":
		method := strings.ToLower(s.Cipher)
		if !slices.Contains(ssMethods, method) {
			return nil, nil, nil, fmt.Errorf("sing-box 不支持 shadowsocks 加密方式 %q", s.Cipher)
		}
		o.Type, o.Method, o.Password, o.UDPOverTCP = "shadowsocks", method, s.Password, s.UDPOverTCP
	case "vmess":
		o.Type, o.UUID, o.Security, o.AlterID = "vmess", s.UUID, cmp.Or(strings.ToLower(s.Cipher), "auto"), s.AlterID
	case "vless":
		// mihomo takes vision-udp443 for vision, which relays UDP/443 anyway.
		o.Type, o.UUID, o.Flow = "vless", s.UUID, strings.TrimSuffix(s.Flow, "-udp443")
	case "trojan":
		o.Type, o.Password = "trojan", s.Password
	case "socks5":
		if s.TLS != nil {
			return nil, nil, nil, fmt.Errorf("sing-box 的 SOCKS5 出站不能套 TLS")
		}
		o.Type, o.Version, o.Username, o.Password = "socks", "5", s.Username, s.Password
	case "http":
		o.Type, o.Username, o.Password, o.Headers = "http", s.Username, s.Password, nonEmpty(s.Headers)
	case "hysteria2":
		o.Type, o.Password = "hysteria2", s.Password
		if h := s.Hysteria; h != nil {
			switch h.Obfs {
			case "":
			case "salamander", "gecko":
				o.Obfs = &obfs{Type: h.Obfs, Password: h.ObfsPassword}
				if h.Obfs == "gecko" {
					o.Obfs.MinPacketSize, o.Obfs.MaxPacketSize = h.ObfsMinPacket, h.ObfsMaxPacket
				}
			default:
				return nil, nil, nil, fmt.Errorf("sing-box 不认识 hysteria2 混淆 %q", h.Obfs)
			}
			o.UpMbps, o.DownMbps = mbps(h.Up), mbps(h.Down)
			if h.Ports != "" {
				o.ServerPorts = serverPorts(h.Ports)
				o.ServerPort = 0
				if h.HopMin > 0 {
					o.HopInterval = strconv.Itoa(h.HopMin) + "s"
				}
				if h.HopMax > h.HopMin {
					o.HopIntervalMax = strconv.Itoa(h.HopMax) + "s" // a random time in the range, as mihomo
				}
			}
		}
		if s.TLS == nil {
			s.TLS = &proto.TLS{} // hysteria2 always runs over TLS
		}
	case "wireguard":
		ep, err := wireguardEndpoint(p.Name, s.WireGuard)
		if err != nil {
			return nil, nil, nil, err
		}
		ep.dial = e.dial(p.Upstream, s.Sockopt)
		return nil, ep, nil, nil
	default:
		return nil, nil, nil, fmt.Errorf("sing-box 后端暂不支持 %s 协议", s.Type)
	}
	if s.TLS != nil {
		t, w := tlsOf(s.TLS, e.opts.Certs)
		o.TLS = t
		warns = append(warns, w...)
	}
	t, err := transportOf(s.Transport, s.TLS != nil, &warns)
	if err != nil {
		return nil, nil, nil, err
	}
	o.Transport = t
	o.dial = e.dial(p.Upstream, s.Sockopt)
	if len(s.Unknown) > 0 {
		warns = append(warns, fmt.Sprintf("这些字段在 sing-box 中没有对应，已忽略：%s", strings.Join(s.Unknown, "、")))
	}
	return o, nil, warns, nil
}

func tlsOf(t *proto.TLS, certs certpin.Lookup) (*tlsOptions, []string) {
	o := &tlsOptions{Enabled: true, ServerName: t.SNI, Insecure: t.Insecure, ALPN: t.ALPN}
	fp, warns := fingerprint(t.Fingerprint)
	if t.Reality != nil {
		fp = cmp.Or(fp, "chrome") // REALITY requires uTLS
		o.Reality = &reality{Enabled: true, PublicKey: t.Reality.PublicKey, ShortID: t.Reality.ShortID}
	}
	if fp != "" {
		o.UTLS = &utls{Enabled: true, Fingerprint: fp}
	}
	if t.PinSHA256 != "" {
		warns = append(warns, pin(o, t.PinSHA256, certs)...)
	}
	return o, warns
}

// pin says what a certificate pin says in sing-box's terms, which need
// the certificate (certpin). A pin is checked whatever skip-cert-verify
// says, as in mihomo; one not learned yet falls back on plain
// verification rather than none.
func pin(o *tlsOptions, sha string, certs certpin.Lookup) []string {
	o.Insecure = false
	if _, ok := certpin.Normalize(sha); !ok {
		return []string{fmt.Sprintf("证书指纹（fingerprint）%q 不是 SHA-256，按常规校验证书", sha)}
	}
	var p certpin.Pin
	ok := certs != nil
	if ok {
		p, ok = certs(sha)
	}
	switch {
	case !ok:
		return []string{"sing-box 要用服务器的证书才能换算证书指纹（fingerprint），conch 还没取到，先按常规校验证书（自签证书会连不上）；取到后会自动换成按指纹校验"}
	case p.PublicKeySHA256 != "":
		o.CertificatePublicKeySHA256 = []string{p.PublicKeySHA256}
	default:
		o.Certificate = strings.Split(strings.TrimSpace(p.CA), "\n")
	}
	return nil
}

func transportOf(t proto.Transport, tls bool, warns *[]string) (*transport, error) {
	headers := map[string]string{}
	for k, v := range t.Headers {
		headers[k] = v
	}
	switch t.Network {
	case "":
		return nil, nil
	case "ws":
		if t.Host != "" {
			headers["Host"] = t.Host // sing-box has no ws host field
		}
		// An empty header name puts early data in the path, as in mihomo.
		return &transport{Type: "ws", Path: t.Path, Headers: nonEmpty(headers), MaxEarlyData: t.EarlyData, EarlyDataHeaderName: t.EarlyDataHeader}, nil
	case "httpupgrade":
		if t.EarlyData > 0 {
			*warns = append(*warns, "sing-box 的 HTTPUpgrade 不支持 early data，这个节点不用 early data")
		}
		o := &transport{Type: "httpupgrade", Path: t.Path, Headers: nonEmpty(headers)}
		if t.Host != "" {
			o.Host = t.Host
		}
		return o, nil
	case "grpc":
		return &transport{Type: "grpc", ServiceName: t.ServiceName}, nil
	case "h2":
		// sing-box's HTTP transport is HTTP/2 over TLS, and HTTP/1.1 without.
		if !tls {
			return nil, fmt.Errorf("h2 传输需要 TLS")
		}
		o := &transport{Type: "http", Path: t.Path, Headers: nonEmpty(headers)}
		if hosts := orOne(t.Hosts, t.Host); len(hosts) > 0 {
			o.Host = hosts
		}
		return o, nil
	case "http":
		// TCP with HTTP request headers: sing-box's HTTP transport without
		// TLS writes them the same way. Over TLS it would be HTTP/2.
		if tls {
			return nil, fmt.Errorf("sing-box 不能在 TLS 里做 HTTP 头部伪装（它的 HTTP 传输在 TLS 上是 HTTP/2）")
		}
		delete(headers, "Host")
		o := &transport{Type: "http", Path: t.Path, Method: t.Method, Headers: nonEmpty(headers)}
		if len(t.Hosts) > 0 {
			o.Host = t.Hosts
		}
		if len(t.Paths) > 1 {
			*warns = append(*warns, fmt.Sprintf("sing-box 的 HTTP 伪装只能用一个路径，用 %s", t.Path))
		}
		return o, nil
	case "xhttp":
		return nil, fmt.Errorf("sing-box 不支持 XHTTP 传输")
	}
	return nil, fmt.Errorf("sing-box 不支持 %s 传输", t.Network)
}

func wireguardEndpoint(tag string, w *proto.WireGuard) (*endpoint, error) {
	if w == nil || len(w.Peers) == 0 {
		return nil, fmt.Errorf("WireGuard 节点缺少对端")
	}
	ep := &endpoint{Type: "wireguard", Tag: tag, Address: w.Address, PrivateKey: w.PrivateKey, MTU: w.MTU}
	for _, p := range w.Peers {
		allowed := p.AllowedIPs
		if len(allowed) == 0 {
			allowed = []string{"0.0.0.0/0", "::/0"}
		}
		ep.Peers = append(ep.Peers, wgPeer{Address: p.Server, Port: p.Port, PublicKey: p.PublicKey, PreSharedKey: p.PreSharedKey, AllowedIPs: allowed, Reserved: p.Reserved})
	}
	return ep, nil
}

// dial sets where an outbound dials from: through the previous hop of a
// chain, or with the node's own socket options.
func (e *encoder) dial(upstream string, s proto.Sockopt) dial {
	d := dial{BindInterface: s.Interface, RoutingMark: s.Mark, TCPFastOpen: s.TFO, TCPMultiPath: s.MPTCP}
	if strategy := ipStrategy[s.IPVersion]; strategy != "" {
		d.DomainResolver = &domainResolver{Server: e.resolver, Strategy: strategy}
	}
	if upstream != "" {
		d = dial{Detour: upstream} // the other dial fields are ignored with a detour
	}
	return d
}

// serverPorts writes hopping ports ("443,20000-30000") the way sing-box
// wants them: every entry a "start:end" range, a single port included.
func serverPorts(ports string) []string {
	var out []string
	for _, r := range strings.Split(ports, ",") {
		r = strings.Replace(strings.TrimSpace(r), "-", ":", 1)
		if r == "" {
			continue
		}
		if !strings.Contains(r, ":") {
			r += ":" + r
		}
		out = append(out, r)
	}
	return out
}

// mbps is bits per second in sing-box's whole Mbps, never rounding a hint
// down to none.
func mbps(bits uint64) int {
	if bits == 0 {
		return 0
	}
	return max(1, int((bits+500_000)/1_000_000))
}

func nonEmpty(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	return m
}

// orOne is a list, or the one value when there is no list.
func orOne(list []string, one string) []string {
	if len(list) > 0 {
		return list
	}
	if one != "" {
		return []string{one}
	}
	return nil
}
