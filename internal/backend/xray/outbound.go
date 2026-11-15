package xray

import (
	"cmp"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/xiongnemo/conch/internal/compile"
	"github.com/xiongnemo/conch/internal/proto"
)

// Shadowsocks methods Xray-core implements; it dropped "none" and "plain".
var ssMethods = []string{
	"aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305",
	"xchacha20-poly1305", "xchacha20-ietf-poly1305",
	"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
}

// nodeOutbound translates one proxy. Problems that make the node unusable
// are returned as errors; lossy translations are reported as warnings.
func (e *encoder) nodeOutbound(p *compile.Proxy) (outbound, []string, error) {
	s := proto.FromClash(p.Node.Raw)
	s.Resolve()
	o := outbound{Tag: e.tags[p.Name]}
	st := &streamSettings{}
	var warns []string
	srv := serverSettings{Address: s.Server, Port: s.Port}

	switch s.Type {
	case "ss":
		if !slices.Contains(ssMethods, strings.ToLower(s.Cipher)) {
			return o, nil, fmt.Errorf("xray 不支持 shadowsocks 加密方式 %q", s.Cipher)
		}
		o.Protocol = "shadowsocks"
		o.Settings = shadowsocksSettings{serverSettings: srv, Method: strings.ToLower(s.Cipher), Password: s.Password}
		if s.UDPOverTCP {
			warns = append(warns, "xray 已不支持 shadowsocks 的 UDP over TCP（udp-over-tcp），这个节点的 UDP 会直接以 UDP 发往服务器")
		}
	case "vmess":
		if s.AlterID != 0 {
			return o, nil, fmt.Errorf("xray 只支持 alterId 为 0 的 VMess（AEAD），这个节点是 %d", s.AlterID)
		}
		security := cmp.Or(strings.ToLower(s.Cipher), "auto")
		if security == "none" || security == "zero" {
			// The client picks the cipher, so the server takes any.
			warns = append(warns, fmt.Sprintf("xray 已不支持 VMess 的 %s 加密，改用 auto", security))
			security = "auto"
		}
		o.Protocol = "vmess"
		o.Settings = vmessSettings{serverSettings: srv, ID: s.UUID, Security: security}
	case "vless":
		flow := s.Flow
		if flow == "xtls-rprx-vision" {
			// xray's plain vision refuses UDP to port 443 (QUIC); mihomo's
			// relays it. The suffix only tells the client; the server sees
			// the same flow.
			flow = "xtls-rprx-vision-udp443"
		}
		o.Protocol = "vless"
		o.Settings = vlessSettings{serverSettings: srv, ID: s.UUID, Flow: flow, Encryption: cmp.Or(s.Encryption, "none")}
	case "trojan":
		o.Protocol = "trojan"
		o.Settings = trojanSettings{serverSettings: srv, Password: s.Password}
	case "socks5":
		o.Protocol = "socks"
		o.Settings = userPassSettings{serverSettings: srv, User: s.Username, Pass: s.Password}
	case "http":
		o.Protocol = "http"
		o.Settings = userPassSettings{serverSettings: srv, User: s.Username, Pass: s.Password, Headers: s.Headers}
	case "hysteria2":
		if p.Upstream != "" && s.Hysteria.Ports != "" {
			// Through a dialerProxy, xray v26.11.9's udphop sends to
			// 0.0.0.0:<port> after its first hop, and the chain goes dead
			// (seen with a real server; sing-box hops through chains fine).
			return o, nil, fmt.Errorf("xray 跳端口后，在链里会连不上：带端口跳跃（ports）的 hysteria2 节点不能放在链里。去掉 ports，或者换用 mihomo、sing-box 内核")
		}
		o.Protocol = "hysteria"
		o.Settings = hysteriaOutSettings{Version: 2, serverSettings: srv}
		st.Network = "hysteria"
		st.HysteriaSettings = &hysteriaSettings{Version: 2, Auth: s.Password}
		st.FinalMask = hysteriaMask(s.Hysteria, &warns)
	case "wireguard":
		o.Protocol = "wireguard"
		o.Settings = wireguardOutSettings(s.WireGuard)
	default:
		return o, nil, fmt.Errorf("xray 不支持 %s 协议", s.Type)
	}

	if s.TLS != nil {
		warns = append(warns, tlsStream(st, s.TLS)...)
	}
	if err := transportStream(st, s.Transport, &warns); err != nil {
		return o, nil, err
	}
	st.Sockopt = e.sockopt(p.Upstream, s.Sockopt)
	// xray refuses a whole config with one of these; better to name the
	// node. (It refuses Trojan without TLS too, which nodes never are.)
	if s.Type == "vless" && st.Security == "" && cmp.Or(s.Encryption, "none") == "none" && requiresEncryption(s.Server) {
		return o, nil, fmt.Errorf("xray 不允许 VLESS 不加密（没有 TLS、REALITY，也没有 VLESS 加密）连接公网服务器")
	}

	if len(s.Unknown) > 0 {
		warns = append(warns, fmt.Sprintf("这些字段在 xray 中没有对应，已忽略：%s", strings.Join(s.Unknown, "、")))
	}
	if *st != (streamSettings{}) {
		o.StreamSettings = st
	}
	return o, warns, nil
}

func tlsStream(st *streamSettings, t *proto.TLS) []string {
	fp, warns := fingerprint(t.Fingerprint)
	if t.Reality != nil {
		if fp == "" || fp == "unsafe" {
			fp = "chrome" // REALITY needs uTLS
		}
		st.Security = "reality"
		st.RealitySettings = &realitySettings{
			ServerName:  t.SNI,
			Fingerprint: fp,
			PublicKey:   t.Reality.PublicKey,
			ShortID:     t.Reality.ShortID,
			SpiderX:     t.Reality.SpiderX,
		}
		return warns
	}
	st.Security = "tls"
	st.TLSSettings = &tlsSettings{ServerName: t.SNI, ALPN: t.ALPN, Fingerprint: fp, PinnedPeerCertSha256: t.PinSHA256}
	if t.Insecure && t.PinSHA256 == "" {
		warns = append(warns, "设置了 skip-cert-verify，但 xray 已移除跳过证书校验的选项，这个节点会正常校验证书；如果服务器用的是自签证书，请在节点上写 fingerprint: <证书 sha256> 来固定证书")
	}
	return warns
}

// fingerprint is mihomo's client-fingerprint in xray's names. "none",
// and names mihomo does not know, mean no uTLS in mihomo: xray's
// "unsafe" (xray refuses names it does not know, a whole config with them).
func fingerprint(name string) (string, []string) {
	switch name = strings.ToLower(name); name {
	case "", "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized":
		return name, nil
	case "none":
		return "unsafe", nil
	case "chrome120":
		return "hellochrome_120", nil
	case "firefox120":
		return "hellofirefox_120", nil
	case "safari16":
		return "safari", []string{"xray 没有 safari16 指纹，改用 safari"}
	case "chrome_psk", "chrome_psk_shuffle", "chrome_padding_psk_shuffle", "chrome_pq", "chrome_pq_psk":
		return "chrome", []string{fmt.Sprintf("xray 没有 %s 指纹（mihomo 也已弃用），改用 chrome", name)}
	}
	return "unsafe", []string{fmt.Sprintf("mihomo 不认识 uTLS 指纹 %q，不会用 uTLS；xray 也不用", name)}
}

func transportStream(st *streamSettings, t proto.Transport, warns *[]string) error {
	switch t.Network {
	case "":
	case "ws":
		path := t.Path
		switch {
		case t.EarlyData == 0:
		case strings.EqualFold(t.EarlyDataHeader, "Sec-WebSocket-Protocol"):
			path = withQuery(path, "ed="+strconv.Itoa(t.EarlyData))
		case t.EarlyDataHeader == "":
			*warns = append(*warns, "xray 不能把 early data 放在路径里（early-data-header-name 为空），这个节点不用 early data")
		default:
			*warns = append(*warns, fmt.Sprintf("xray 只能通过 Sec-WebSocket-Protocol 发送 early data，不支持 %s，这个节点不用 early data", t.EarlyDataHeader))
		}
		st.Network = "ws"
		st.WSSettings = &httpSettings{Host: t.Host, Path: path, Headers: nonEmpty(t.Headers)}
	case "httpupgrade":
		if t.EarlyData > 0 {
			*warns = append(*warns, "xray 的 HTTPUpgrade 不支持 early data，这个节点不用 early data")
		}
		st.Network = "httpupgrade"
		st.HTTPUpgradeSettings = &httpSettings{Host: t.Host, Path: t.Path, Headers: nonEmpty(t.Headers)}
	case "grpc":
		st.Network = "grpc"
		st.GRPCSettings = &grpcSettings{ServiceName: t.ServiceName}
	case "xhttp":
		st.Network = "xhttp"
		st.XHTTPSettings = &xhttpSettings{Host: t.Host, Path: t.Path, Mode: t.Mode, Headers: nonEmpty(t.Headers)}
	case "http":
		// HTTP request-header obfuscation over raw TCP. Resolve filled in
		// mihomo's method, paths and host; xray's own defaults differ.
		req := &rawRequest{Method: t.Method, Path: t.Paths, Headers: map[string][]string{"Host": t.Hosts}}
		for k, v := range t.Headers {
			req.Headers[k] = []string{v}
		}
		st.Network = "raw"
		st.RawSettings = &rawSettings{Header: rawHeader{Type: "http", Request: req}}
	case "h2":
		return fmt.Errorf("xray 已移除 h2 传输（官方建议迁移到 XHTTP）")
	default:
		return fmt.Errorf("xray 不支持 %s 传输", t.Network)
	}
	return nil
}

// bps writes bits per second the way xray reads them exactly.
func bps(bits uint64) string {
	if bits == 0 {
		return ""
	}
	return fmt.Sprintf("%d bps", bits)
}

func hysteriaMask(h *proto.Hysteria, warns *[]string) *finalMask {
	m := &finalMask{}
	if h.Ports != "" {
		// Port hopping as Hysteria 2 does it: now and then another port of
		// the server, from another local socket. It opens the sockets
		// itself, so it must be the first mask.
		lo, hi := h.HopMin, h.HopMax
		if lo > 0 && lo < 5 {
			*warns = append(*warns, fmt.Sprintf("xray 的端口跳跃间隔至少 5 秒，hop-interval 的 %d 改为 5", lo))
			lo, hi = 5, max(hi, 5)
		}
		var interval any
		switch {
		case hi > lo:
			interval = fmt.Sprintf("%d-%d", lo, hi) // a random time in the range, as mihomo
		case lo > 0:
			interval = lo
		}
		m.UDP = append(m.UDP, mask{Type: "udphop", Settings: udpHopSettings{Mode: "intervalLocal,intervalRemote", Interval: interval, RemotePorts: strings.ReplaceAll(h.Ports, ":", "-")}})
	}
	switch h.Obfs {
	case "":
	case "salamander":
		m.UDP = append(m.UDP, mask{Type: "salamander", Settings: salamanderSettings{Password: h.ObfsPassword}})
	case "gecko":
		// xray's gecko is salamander with packet sizes; Hysteria's are 512-1200.
		lo, hi := cmp.Or(h.ObfsMinPacket, 512), cmp.Or(h.ObfsMaxPacket, 1200)
		m.UDP = append(m.UDP, mask{Type: "salamander", Settings: salamanderSettings{Password: h.ObfsPassword, PacketSize: fmt.Sprintf("%d-%d", lo, hi)}})
	default:
		*warns = append(*warns, fmt.Sprintf("xray 不认识 hysteria2 混淆 %q，这个节点不混淆", h.Obfs))
	}
	q := &quicParams{}
	if h.Up != 0 || h.Down != 0 {
		// Bandwidth hints mean Brutal congestion control, as in Hysteria 2.
		// xray reads every unit as bits, "bps" exactly, and takes no less
		// than 64 KiB/s.
		const least = 65536 * 8
		up, down := h.Up, h.Down
		for _, b := range []*uint64{&up, &down} {
			if *b != 0 && *b < least {
				*warns = append(*warns, fmt.Sprintf("xray 的带宽提示最少 512 Kbps，%s 改为 512 Kbps", proto.FormatBandwidth(*b)))
				*b = least
			}
		}
		q.Congestion, q.BrutalUp, q.BrutalDown = "brutal", bps(up), bps(down)
	}
	if *q != (quicParams{}) {
		m.QuicParams = q
	}
	if m.UDP == nil && m.QuicParams == nil {
		return nil
	}
	return m
}

func wireguardOutSettings(w *proto.WireGuard) wireguardSettings {
	out := wireguardSettings{SecretKey: w.PrivateKey, Address: w.Address, MTU: w.MTU}
	for _, p := range w.Peers {
		out.Peers = append(out.Peers, wireguardPeer{
			PublicKey:    p.PublicKey,
			PreSharedKey: p.PreSharedKey,
			Endpoint:     net.JoinHostPort(p.Server, strconv.Itoa(p.Port)),
			AllowedIPs:   p.AllowedIPs,
		})
		if out.Reserved == nil {
			out.Reserved = p.Reserved // xray keeps reserved bytes per interface
		}
	}
	return out
}

// ipVersionStrategy is mihomo's ip-version in xray's terms: the Force
// strategies, since the Use ones fall back to the system's resolver when
// a lookup fails, which mihomo never does. dual is what both do anyway.
var ipVersionStrategy = map[string]string{
	"ipv4":        "ForceIPv4",
	"ipv6":        "ForceIPv6",
	"ipv4-prefer": "ForceIPv4v6",
	"ipv6-prefer": "ForceIPv6v4",
}

func (e *encoder) sockopt(upstream string, s proto.Sockopt) *sockopt {
	o := &sockopt{
		DomainStrategy: ipVersionStrategy[s.IPVersion],
		TCPFastOpen:    s.TFO,
		TCPMptcp:       s.MPTCP,
		Interface:      s.Interface,
		Mark:           s.Mark,
	}
	if upstream != "" {
		o.DialerProxy = e.tags[upstream]
	}
	if *o == (sockopt{}) {
		return nil
	}
	return o
}

func withQuery(path, q string) string {
	if path == "" {
		path = "/"
	}
	if strings.Contains(path, "?") {
		return path + "&" + q
	}
	return path + "?" + q
}

func nonEmpty(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	return m
}
