package singbox

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"nautilus/internal/compile"
	"nautilus/internal/proto"
)

// Shadowsocks methods sing-box implements.
var ssMethods = []string{
	"none", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
	"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
	"aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "rc4-md5", "chacha20-ietf", "xchacha20",
}

// uTLS fingerprints sing-box accepts.
var fingerprints = []string{"chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android", "random", "randomized"}

// nodeOutbound translates one proxy. WireGuard nodes become endpoints.
// Problems that make the node unusable are errors; lossy translations
// are reported as warnings.
func (e *encoder) nodeOutbound(p *compile.Proxy) (*outbound, *endpoint, []string, error) {
	s := proto.FromClash(p.Node.Raw)
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
		o.Type, o.UUID, o.Security = "vmess", s.UUID, cmp.Or(strings.ToLower(s.Cipher), "auto")
		if s.AlterID != 0 {
			warns = append(warns, "sing-box 只支持 alterId 为 0 的 VMess（AEAD），这个节点很可能连不上")
		}
	case "vless":
		o.Type, o.UUID, o.Flow = "vless", s.UUID, s.Flow
	case "trojan":
		o.Type, o.Password = "trojan", s.Password
	case "socks5":
		o.Type, o.Version, o.Username, o.Password = "socks", "5", s.Username, s.Password
	case "http":
		o.Type, o.Username, o.Password, o.Headers = "http", s.Username, s.Password, nonEmpty(s.Headers)
	case "hysteria2":
		o.Type, o.Password = "hysteria2", s.Password
		if h := s.Hysteria; h != nil {
			if h.Obfs != "" {
				o.Obfs = &obfs{Type: h.Obfs, Password: h.ObfsPassword}
			}
			o.UpMbps, o.DownMbps = mbps(h.Up), mbps(h.Down)
			if h.Ports != "" {
				// sing-box writes ranges as "start:end" and wants no server_port then.
				for _, r := range strings.Split(h.Ports, ",") {
					o.ServerPorts = append(o.ServerPorts, strings.Replace(strings.TrimSpace(r), "-", ":", 1))
				}
				o.ServerPort = 0
				if h.HopInterval > 0 {
					o.HopInterval = strconv.Itoa(h.HopInterval) + "s"
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
		t, w := tlsOf(s.TLS)
		o.TLS = t
		warns = append(warns, w...)
	}
	t, err := transportOf(s.Transport, &warns)
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

func tlsOf(t *proto.TLS) (*tlsOptions, []string) {
	o := &tlsOptions{Enabled: true, ServerName: t.SNI, Insecure: t.Insecure, ALPN: t.ALPN}
	var warns []string
	fp := strings.ToLower(t.Fingerprint)
	if fp != "" && !slices.Contains(fingerprints, fp) {
		warns = append(warns, fmt.Sprintf("sing-box 不认识 uTLS 指纹 %q，改用 chrome", t.Fingerprint))
		fp = "chrome"
	}
	if t.Reality != nil {
		fp = cmp.Or(fp, "chrome") // REALITY requires uTLS
		o.Reality = &reality{Enabled: true, PublicKey: t.Reality.PublicKey, ShortID: t.Reality.ShortID}
	}
	if fp != "" {
		o.UTLS = &utls{Enabled: true, Fingerprint: fp}
	}
	if t.PinSHA256 != "" {
		// mihomo pins the certificate's hash; sing-box only the public key's.
		warns = append(warns, "sing-box 只能固定证书公钥的 sha256，无法使用节点上的证书指纹（fingerprint），已忽略")
	}
	return o, warns
}

func transportOf(t proto.Transport, warns *[]string) (*transport, error) {
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
		o := &transport{Type: "ws", Path: t.Path, Headers: nonEmpty(headers), MaxEarlyData: t.EarlyData}
		if t.EarlyData > 0 {
			o.EarlyDataHeaderName = cmp.Or(t.EarlyDataHeader, "Sec-WebSocket-Protocol")
		}
		return o, nil
	case "httpupgrade":
		o := &transport{Type: "httpupgrade", Path: t.Path, Headers: nonEmpty(headers)}
		if t.Host != "" {
			o.Host = t.Host
		}
		return o, nil
	case "grpc":
		return &transport{Type: "grpc", ServiceName: t.ServiceName}, nil
	case "h2", "http":
		o := &transport{Type: "http", Path: t.Path, Headers: nonEmpty(headers)}
		if t.Host != "" {
			o.Host = []string{t.Host}
		}
		if t.Network == "http" {
			*warns = append(*warns, "sing-box 没有 TCP 上的 HTTP 头部伪装，改用 HTTP 传输，服务器也需要是 HTTP 传输")
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
	if upstream != "" {
		d = dial{Detour: upstream} // the other dial fields are ignored with a detour
	}
	return d
}

// mbps reads a bandwidth like "100 Mbps" or "100" as megabits per second.
func mbps(s string) int {
	s = strings.ToLower(strings.TrimSpace(s))
	n := strings.TrimRight(strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(s, "mbps"), "m")), " ")
	v, err := strconv.Atoi(n)
	if err != nil {
		return 0
	}
	return v
}

func nonEmpty(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	return m
}
