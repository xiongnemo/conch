package singbox

import (
	"cmp"
	"encoding/base64"
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
		o.Type, o.Method, o.Password = "shadowsocks", method, s.Password
		if s.UDPOverTCP {
			// sing-box's default is version 2, mihomo's 1.
			o.UDPOverTCP = &udpOverTCP{Enabled: true, Version: cmp.Or(s.UoTVersion, 1)}
		}
		if pl := s.Plugin; pl != nil {
			w, err := e.plugin(o, p, s)
			if err != nil {
				return nil, nil, nil, err
			}
			warns = append(warns, w...)
		}
	case "vmess":
		o.Type, o.UUID, o.Security, o.AlterID = "vmess", s.UUID, cmp.Or(strings.ToLower(s.Cipher), "auto"), s.AlterID
		o.GlobalPadding, o.AuthLength, o.PacketEncoding = s.GlobalPadding, s.AuthenticatedLength, s.PacketEncoding
	case "vless":
		// mihomo takes vision-udp443 for vision, which relays UDP/443 anyway.
		o.Type, o.UUID, o.Flow, o.PacketEncoding = "vless", s.UUID, strings.TrimSuffix(s.Flow, "-udp443"), s.PacketEncoding
		if e := s.Encryption; e != "" && e != "none" {
			return nil, nil, nil, fmt.Errorf("sing-box 没有 VLESS 加密（encryption: %s）", e)
		}
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
				ob := &obfs{Type: h.Obfs, Password: h.ObfsPassword}
				if h.Obfs == "gecko" {
					ob.MinPacketSize, ob.MaxPacketSize = h.ObfsMinPacket, h.ObfsMaxPacket
				}
				o.Obfs = ob
			default:
				return nil, nil, nil, fmt.Errorf("sing-box 不认识 hysteria2 混淆 %q", h.Obfs)
			}
			o.UpMbps, o.DownMbps = mbps(h.Up), mbps(h.Down)
			if rl := h.Realm; rl != nil {
				// The realm finds the server; sing-box takes no address with it.
				o.Realm = &realm{ServerURL: rl.ServerURL, Token: rl.Token, RealmID: rl.RealmID, STUNServers: rl.STUN}
				if rl.TLS != nil && strings.HasPrefix(rl.ServerURL, "https") {
					t, w := tlsOf(rl.TLS, e.opts.Certs)
					o.Realm.HTTPClient = &httpClient{TLS: t}
					warns = append(warns, w...)
				}
				o.Server, o.ServerPort, h.Ports = "", 0, ""
			}
			// sing-box sets one window of each kind, which quic-go grows to.
			o.BBRProfile, o.StreamWindow, o.ConnWindow = h.BBRProfile, cmp.Or(h.MaxStreamWindow, h.InitStreamWindow), cmp.Or(h.MaxConnWindow, h.InitConnWindow)
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
	case "hysteria":
		h := s.Hysteria
		switch h.Protocol {
		case "", "udp":
		default:
			return nil, nil, nil, fmt.Errorf("sing-box 的 hysteria 只能走 UDP，不支持 %s", h.Protocol)
		}
		o.Type, o.AuthStr, o.UpMbps, o.DownMbps = "hysteria", s.Password, mbps(h.Up), mbps(h.Down)
		if h.ObfsPassword != "" {
			o.Obfs = h.ObfsPassword
		}
		if h.Auth != "" {
			auth, err := base64.StdEncoding.DecodeString(h.Auth)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("hysteria 的 auth 不是 base64")
			}
			o.Auth = auth
		}
		o.StreamWindow, o.ConnWindow = h.InitStreamWindow, h.InitConnWindow
		if h.Ports != "" {
			o.ServerPorts, o.ServerPort = serverPorts(h.Ports), 0
			o.HopInterval = strconv.Itoa(h.HopMin) + "s" // mihomo's default is 10, sing-box's 30
		}
	case "tuic":
		t := s.TUIC
		if t.Token != "" {
			return nil, nil, nil, fmt.Errorf("sing-box 只有 TUIC v5，没有 v4（token）")
		}
		o.Type, o.UUID, o.Password = "tuic", s.UUID, s.Password
		o.Congestion, o.UDPRelayMode, o.UDPOverStream, o.ZeroRTT = t.Congestion, t.UDPRelayMode, t.UDPOverStream, t.ReduceRTT
		if strings.HasPrefix(t.Congestion, "bbr") {
			o.Congestion = "bbr" // mihomo's bbr_meta_v1 and v2 are its own BBRs
		}
		if t.Heartbeat > 0 {
			o.Heartbeat = strconv.Itoa(t.Heartbeat) + "ms"
		}
	case "anytls":
		a := s.AnyTLS
		o.Type, o.Password, o.MinIdle = "anytls", s.Password, a.MinIdle
		if a.IdleCheck > 0 {
			o.IdleCheck = strconv.Itoa(a.IdleCheck) + "s"
		}
		if a.IdleTimeout > 0 {
			o.IdleTimeout2 = strconv.Itoa(a.IdleTimeout) + "s"
		}
		if s.Sockopt.TFO {
			warns = append(warns, "sing-box 的 anytls 不能用 TCP Fast Open（tfo）")
			s.Sockopt.TFO = false
		}
	case "ssh":
		x := s.SSH
		o.Type, o.User, o.Password, o.KeyPassphrase, o.HostKey, o.HostKeyAlgos = "ssh", s.Username, s.Password, x.Passphrase, x.HostKeys, x.HostKeyAlgorithms
		if x.PrivateKey != "" {
			if pem := pemLines(x.PrivateKey); pem != nil {
				o.PrivateKey = pem
			} else {
				o.PrivateKeyPath = x.PrivateKey
			}
		}
	case "direct":
		o.Type, o.Server, o.ServerPort = "direct", "", 0
	case "reject":
		return &outbound{Type: "block", Tag: p.Name}, nil, nil, nil
	case "wireguard":
		if len(s.WireGuard.Amnezia) > 0 {
			return nil, nil, nil, fmt.Errorf("sing-box 没有 AmneziaWG（amnezia-wg-option）")
		}
		if s.WireGuard.RemoteDNS && len(s.WireGuard.DNS) > 0 {
			warns = append(warns, "sing-box 在本地解析经由 WireGuard 的域名，不能经由隧道用节点的 dns 解析（remote-dns-resolve）")
		}
		ep, err := wireguardEndpoint(p.Name, s.WireGuard)
		if err != nil {
			return nil, nil, nil, err
		}
		ep.dial = e.dial(p.Upstream, s.Sockopt)
		return nil, ep, warns, nil
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
	if x := s.Mux; x != nil {
		switch s.Type {
		case "ss", "vmess", "vless", "trojan":
			o.Multiplex = &multiplex{Enabled: true, Protocol: x.Protocol, MaxConnections: x.MaxConnections, MinStreams: x.MinStreams, MaxStreams: x.MaxStreams, Padding: x.Padding}
			if x.BrutalUp > 0 || x.BrutalDown > 0 {
				o.Multiplex.Brutal = &brutal{Enabled: true, UpMbps: mbps(x.BrutalUp), DownMbps: mbps(x.BrutalDown)}
			}
		default:
			warns = append(warns, "sing-box 只能给 ss、vmess、vless、trojan 用多路复用（smux），这个节点不用")
		}
	}
	if o.Detour == "" { // shadow-tls dials for it
		o.dial = e.dial(p.Upstream, s.Sockopt)
	}
	if len(s.Unknown) > 0 {
		warns = append(warns, fmt.Sprintf("这些字段在 sing-box 中没有对应，已忽略：%s", strings.Join(s.Unknown, "、")))
	}
	return o, nil, warns, nil
}

func tlsOf(t *proto.TLS, certs certpin.Lookup) (*tlsOptions, []string) {
	o := &tlsOptions{Enabled: true, ServerName: t.SNI, Insecure: t.Insecure, ALPN: t.ALPN, DisableSNI: t.DisableSNI}
	fp, warns := fingerprint(t.Fingerprint)
	if t.VerifyName != "" {
		warns = append(warns, fmt.Sprintf("sing-box 不能按 %s 校验证书（name-cert-verify），按 SNI 校验", t.VerifyName))
	}
	if t.Certificate != "" {
		if pem := pemLines(t.Certificate); pem != nil {
			o.ClientCertificate = pem
		} else {
			o.ClientCertificatePath = []string{t.Certificate}
		}
	}
	if t.PrivateKey != "" {
		if pem := pemLines(t.PrivateKey); pem != nil {
			o.ClientKey = pem
		} else {
			o.ClientKeyPath = t.PrivateKey
		}
	}
	if e := t.ECH; e != nil {
		o.ECH = &ech{Enabled: true, QueryServerName: e.QueryServerName}
		if e.Config != "" {
			o.ECH.Config = echPEM(e.Config)
		}
	}
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
		o := &transport{Type: "grpc", ServiceName: t.ServiceName}
		if t.PingInterval > 0 {
			o.IdleTimeout = strconv.Itoa(t.PingInterval) + "s"
		}
		if t.UserAgent != "" {
			*warns = append(*warns, "sing-box 不能设置 gRPC 的 User-Agent（grpc-user-agent）")
		}
		return o, nil
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
	ep := &endpoint{Type: "wireguard", Tag: tag, Address: w.Address, PrivateKey: w.PrivateKey, MTU: w.MTU, Workers: w.Workers}
	for _, p := range w.Peers {
		allowed := p.AllowedIPs
		if len(allowed) == 0 {
			allowed = []string{"0.0.0.0/0", "::/0"}
		}
		ep.Peers = append(ep.Peers, wgPeer{Address: p.Server, Port: p.Port, PublicKey: p.PublicKey, PreSharedKey: p.PreSharedKey, AllowedIPs: allowed, Reserved: p.Reserved, Keepalive: w.Keepalive})
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

// pemLines is PEM content as sing-box's line arrays, or nil for a path.
func pemLines(s string) []string {
	if !strings.Contains(s, "-----BEGIN") {
		return nil
	}
	return strings.Split(strings.TrimSpace(s), "\n")
}

// echPEM wraps an ECH config list, base64 as mihomo writes it, in the
// PEM block sing-box reads.
func echPEM(config string) []string {
	config = strings.Join(strings.Fields(config), "")
	lines := []string{"-----BEGIN ECH CONFIGS-----"}
	for len(config) > 64 {
		lines, config = append(lines, config[:64]), config[64:]
	}
	return append(lines, config, "-----END ECH CONFIGS-----")
}

// plugin translates a shadowsocks plugin: obfs and v2ray-plugin are
// sing-box's own SIP003 plugins; shadow-tls is an outbound the node dials
// through.
func (e *encoder) plugin(o *outbound, p *compile.Proxy, s *proto.Spec) ([]string, error) {
	pl := s.Plugin
	var warns []string
	switch pl.Name {
	case "obfs":
		o.Plugin, o.PluginOpts = "obfs-local", sip003("obfs", pl.Mode, "obfs-host", pl.Host)
	case "v2ray-plugin":
		if pl.HTTPUpgrade {
			return nil, fmt.Errorf("sing-box 的 v2ray-plugin 只有 WebSocket，没有 HTTPUpgrade（v2ray-http-upgrade）")
		}
		mux := "0"
		if pl.Mux {
			mux = "1"
		}
		opts := []string{"mode", cmp.Or(pl.Mode, "websocket"), "host", pl.Host, "path", cmp.Or(pl.Path, "/"), "mux", mux}
		if t := pl.TLS; t != nil {
			opts = append(opts, "tls", "")
			switch {
			case t.Insecure || t.PinSHA256 != "":
				warns = append(warns, "sing-box 的 v2ray-plugin 不能跳过或固定证书，按常规校验")
			case t.ECH != nil || t.Certificate != "" || t.VerifyName != "":
				warns = append(warns, "sing-box 的 v2ray-plugin 没有 ECH、客户端证书和 name-cert-verify")
			}
		}
		if len(pl.Headers) > 0 {
			warns = append(warns, "sing-box 的 v2ray-plugin 不能加请求头（headers）")
		}
		o.Plugin, o.PluginOpts = "v2ray-plugin", sip003(opts...)
	case "shadow-tls":
		tag := p.Name + compile.HopSep + "shadow-tls"
		st := outbound{Type: "shadowtls", Tag: tag, Server: s.Server, ServerPort: s.Port, Version: pl.Version, Password: pl.Password}
		t, w := tlsOf(pl.TLS, e.opts.Certs)
		st.TLS, warns = t, w
		st.dial = e.dial(p.Upstream, s.Sockopt)
		e.extra = append(e.extra, st)
		o.dial = dial{Detour: tag}
	default:
		return nil, fmt.Errorf("sing-box 没有 %s 插件", pl.Name)
	}
	return warns, nil
}

// sip003 writes plugin options, key, value, …, the way SIP003 has them:
// key=value;… with ; = and \ escaped; an empty value is a flag.
func sip003(kv ...string) string {
	esc := strings.NewReplacer(`\`, `\\`, ";", `\;`, "=", `\=`)
	var parts []string
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" && kv[i] != "tls" {
			continue
		}
		part := esc.Replace(kv[i])
		if kv[i+1] != "" {
			part += "=" + esc.Replace(kv[i+1])
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, ";")
}
