package singbox

import (
	"strings"
	"testing"

	"github.com/xiongnemo/conch/internal/backend/backendtest"
)

// Nodes sing-box takes in its own terms, nodes it cannot take as said,
// and what it says about them.
func TestNodeTranslations(t *testing.T) {
	for _, c := range []struct {
		node   string
		err    bool
		said   string // in the diagnostics
		config string // in the config
	}{
		// sing-box does VMess with alterId, unlike xray.
		{node: `{ name: m, type: vmess, server: 192.0.2.1, port: 443, uuid: 11111111-2222-3333-4444-555555555555, alterId: 64, cipher: auto }`, config: `"alter_id": 64`},
		// mihomo reads vision-udp443 as vision.
		{node: `{ name: v, type: vless, server: 192.0.2.1, port: 443, uuid: 11111111-2222-3333-4444-555555555555, tls: true, flow: xtls-rprx-vision-udp443 }`, config: `"flow": "xtls-rprx-vision"`},
		{node: `{ name: s, type: socks5, server: 192.0.2.1, port: 1080, tls: true }`, err: true, said: "SOCKS5 出站不能套 TLS"},
		{node: `{ name: h, type: vmess, server: 192.0.2.1, port: 443, uuid: 11111111-2222-3333-4444-555555555555, tls: true, network: http }`, err: true, said: "不能在 TLS 里做 HTTP 头部伪装"},
		{node: `{ name: h, type: vmess, server: 192.0.2.1, port: 80, uuid: 11111111-2222-3333-4444-555555555555, network: h2 }`, err: true, said: "h2 传输需要 TLS"},
		// mihomo's unknown names mean no uTLS.
		{node: `{ name: f, type: trojan, server: 192.0.2.1, port: 443, password: p, client-fingerprint: nonsense }`, said: "mihomo 不认识 uTLS 指纹"},
		// An empty header name puts early data in the path, in both.
		{node: `{ name: w, type: trojan, server: 192.0.2.1, port: 443, password: p, network: ws, ws-opts: { path: /w, max-early-data: 2048 } }`, config: `"max_early_data": 2048`},
		{node: `{ name: o, type: hysteria2, server: 192.0.2.1, port: 443, password: p, obfs: nonsense, obfs-password: x }`, err: true, said: "不认识 hysteria2 混淆"},
		{node: `{ name: e, type: vless, server: 192.0.2.1, port: 443, uuid: 11111111-2222-3333-4444-555555555555, tls: true, encryption: mlkem768x25519plus.native.0rtt.x }`, err: true, said: "sing-box 没有 VLESS 加密"},
		// A client certificate: a file, or PEM in the node.
		{node: `{ name: c, type: trojan, server: 192.0.2.1, port: 443, password: p, certificate: /etc/conch/c.pem, private-key: /etc/conch/k.pem }`, config: `"client_key_path": "/etc/conch/k.pem"`},
		{node: `{ name: c, type: trojan, server: 192.0.2.1, port: 443, password: p, certificate: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----", private-key: /k.pem }`, config: `"MIIB"`},
		{node: `{ name: u, type: ss, server: 192.0.2.1, port: 1, cipher: aes-128-gcm, password: p, udp-over-tcp: true }`, config: `"version": 1`},
		// mihomo's snell is version 1 unless written; sing-box only has 4.
		{node: `{ name: n, type: snell, server: 192.0.2.1, port: 443, psk: k }`, err: true, said: "sing-box 只有 snell 第 4 版，这个节点是第 1 版"},
		{node: `{ name: n, type: snell, server: 192.0.2.1, port: 443, psk: k, version: 4, obfs-opts: { mode: tls } }`, config: `"obfs_host": "bing.com"`},
		{node: `{ name: n, type: snell, server: 192.0.2.1, port: 443, psk: k, version: 4, obfs-opts: { mode: restls, host: r.example.com } }`, err: true, said: "snell 没有 restls 混淆"},
	} {
		art, said := backendtest.BuildNode(t, Backend{}, c.node)
		switch {
		case c.err != (art == nil):
			t.Errorf("%s: config made: %v\n%s", c.node, art != nil, said)
		case !strings.Contains(said, c.said):
			t.Errorf("%s: want %q said:\n%s", c.node, c.said, said)
		case c.config != "" && !strings.Contains(string(art.Config), c.config):
			t.Errorf("%s: config lacks %s:\n%s", c.node, c.config, art.Config)
		}
		if c.config == `"max_early_data": 2048` && art != nil && strings.Contains(string(art.Config), "early_data_header_name") {
			t.Errorf("%s: early data moved to a header", c.node)
		}
	}
}
