package xray

import (
	"cmp"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	"nautilus/internal/compile"
	"nautilus/internal/proto"
)

// Shadowsocks methods Xray-core implements.
var ssMethods = []string{
	"aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305",
	"xchacha20-poly1305", "xchacha20-ietf-poly1305", "none", "plain",
	"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
}

// nodeOutbound translates one proxy. Problems that make the node unusable
// are returned as errors; lossy translations are reported as warnings.
func (e *encoder) nodeOutbound(p *compile.Proxy) (outbound, []string, error) {
	s := proto.FromClash(p.Node.Raw)
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
		o.Settings = shadowsocksSettings{serverSettings: srv, Method: strings.ToLower(s.Cipher), Password: s.Password, UoT: s.UDPOverTCP}
	case "vmess":
		if s.AlterID != 0 {
			return o, nil, fmt.Errorf("xray 只支持 alterId 为 0 的 VMess（AEAD），这个节点是 %d", s.AlterID)
		}
		o.Protocol = "vmess"
		o.Settings = vmessSettings{serverSettings: srv, ID: s.UUID, Security: cmp.Or(strings.ToLower(s.Cipher), "auto")}
	case "vless":
		o.Protocol = "vless"
		o.Settings = vlessSettings{serverSettings: srv, ID: s.UUID, Flow: s.Flow, Encryption: cmp.Or(s.Encryption, "none")}
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
		o.Protocol = "hysteria"
		o.Settings = hysteriaOutSettings{Version: 2, serverSettings: srv}
		st.Network = "hysteria"
		st.HysteriaSettings = &hysteriaSettings{Version: 2, Auth: s.Password}
		st.FinalMask = hysteriaMask(s.Hysteria)
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

	if len(s.Unknown) > 0 {
		warns = append(warns, fmt.Sprintf("这些字段在 xray 中没有对应，已忽略：%s", strings.Join(s.Unknown, "、")))
	}
	if *st != (streamSettings{}) {
		o.StreamSettings = st
	}
	return o, warns, nil
}

func tlsStream(st *streamSettings, t *proto.TLS) []string {
	if t.Reality != nil {
		st.Security = "reality"
		st.RealitySettings = &realitySettings{
			ServerName:  t.SNI,
			Fingerprint: cmp.Or(t.Fingerprint, "chrome"), // REALITY requires one
			PublicKey:   t.Reality.PublicKey,
			ShortID:     t.Reality.ShortID,
			SpiderX:     t.Reality.SpiderX,
		}
		return nil
	}
	st.Security = "tls"
	st.TLSSettings = &tlsSettings{ServerName: t.SNI, ALPN: t.ALPN, Fingerprint: t.Fingerprint, PinnedPeerCertSha256: t.PinSHA256}
	if t.Insecure && t.PinSHA256 == "" {
		return []string{"设置了 skip-cert-verify，但 xray 已移除跳过证书校验的选项，这个节点会正常校验证书；如果服务器用的是自签证书，请在节点上写 fingerprint: <证书 sha256> 来固定证书"}
	}
	return nil
}

func transportStream(st *streamSettings, t proto.Transport, warns *[]string) error {
	switch t.Network {
	case "":
	case "ws":
		path := t.Path
		if t.EarlyData > 0 {
			if t.EarlyDataHeader != "" && !strings.EqualFold(t.EarlyDataHeader, "Sec-WebSocket-Protocol") {
				*warns = append(*warns, fmt.Sprintf("xray 只能通过 Sec-WebSocket-Protocol 发送 early data，不支持 %s", t.EarlyDataHeader))
			}
			path = withQuery(path, "ed="+strconv.Itoa(t.EarlyData))
		}
		st.Network = "ws"
		st.WSSettings = &httpSettings{Host: t.Host, Path: path, Headers: nonEmpty(t.Headers)}
	case "httpupgrade":
		st.Network = "httpupgrade"
		st.HTTPUpgradeSettings = &httpSettings{Host: t.Host, Path: t.Path, Headers: nonEmpty(t.Headers)}
	case "grpc":
		st.Network = "grpc"
		st.GRPCSettings = &grpcSettings{ServiceName: t.ServiceName}
	case "xhttp":
		st.Network = "xhttp"
		st.XHTTPSettings = &xhttpSettings{Host: t.Host, Path: t.Path, Mode: t.Mode, Headers: nonEmpty(t.Headers)}
	case "http":
		// HTTP request-header obfuscation over raw TCP.
		req := &rawRequest{}
		if t.Path != "" {
			req.Path = []string{t.Path}
		}
		if t.Host != "" {
			req.Headers = map[string][]string{"Host": {t.Host}}
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

func hysteriaMask(h *proto.Hysteria) *finalMask {
	m := &finalMask{}
	if h.Obfs != "" {
		m.UDP = []mask{{Type: h.Obfs, Settings: map[string]string{"password": h.ObfsPassword}}}
	}
	q := &quicParams{}
	if h.Up != "" || h.Down != "" {
		// Bandwidth hints mean Brutal congestion control, as in Hysteria 2.
		q.Congestion, q.BrutalUp, q.BrutalDown = "brutal", h.Up, h.Down
	}
	if h.Ports != "" {
		q.UDPHop = &udpHop{Ports: h.Ports, Interval: h.HopInterval}
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

var ipVersionStrategy = map[string]string{
	"ipv4":        "UseIPv4",
	"ipv6":        "UseIPv6",
	"ipv4-prefer": "UseIPv4v6",
	"ipv6-prefer": "UseIPv6v4",
	"dual":        "UseIP",
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
