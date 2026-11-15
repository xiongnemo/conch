package proto

import (
	"reflect"
	"testing"
)

// What mihomo does without being told, spelled out.
func TestResolve(t *testing.T) {
	ws := decode(t, `{ name: a, type: vmess, server: s, port: 443, uuid: u, tls: true, alpn: [h2], network: ws,
		ws-opts: { path: "/p?ed=2048&x=1", headers: { Host: cdn.example } } }`)
	ws.Resolve()
	if ws.TLS.SNI != "cdn.example" || !reflect.DeepEqual(ws.TLS.ALPN, []string{"http/1.1"}) ||
		ws.Transport.Path != "/p?x=1" || ws.Transport.EarlyData != 2048 || ws.Transport.EarlyDataHeader != "Sec-WebSocket-Protocol" {
		t.Errorf("vmess ws: %+v %+v", ws.TLS, ws.Transport)
	}
	tr := decode(t, `{ name: a, type: trojan, server: s, port: 443, password: p, sni: t.example, network: ws, ws-opts: { path: /w } }`)
	tr.Resolve()
	if tr.Transport.Host != "t.example" || !reflect.DeepEqual(tr.TLS.ALPN, []string{"http/1.1"}) {
		t.Errorf("trojan ws: %+v %+v", tr.TLS, tr.Transport)
	}
	tcp := decode(t, `{ name: a, type: trojan, server: s, port: 443, password: p, alpn: [h2] }`)
	tcp.Resolve()
	if !reflect.DeepEqual(tcp.TLS.ALPN, []string{"h2"}) {
		t.Errorf("trojan with its own ALPN: %v", tcp.TLS.ALPN)
	}
	h := decode(t, `{ name: a, type: vmess, server: s.example, port: 80, uuid: u, network: http }`)
	h.Resolve()
	if h.Transport.Method != "GET" || !reflect.DeepEqual(h.Transport.Paths, []string{"/"}) || !reflect.DeepEqual(h.Transport.Hosts, []string{"s.example"}) {
		t.Errorf("http: %+v", h.Transport)
	}
	wg := decode(t, `{ name: a, type: wireguard, server: s, port: 1, private-key: k, public-key: p }`)
	wg.Resolve()
	if wg.WireGuard.MTU != 1408 {
		t.Errorf("WireGuard MTU %d", wg.WireGuard.MTU)
	}
	hy := decode(t, `{ name: a, type: hysteria2, server: s, port: 443, password: p, ports: "443/1000-2000", hop-interval: "10-30",
		client-fingerprint: chrome, reality-opts: { public-key: k } }`)
	if hy.Hysteria.Ports != "443,1000-2000" || hy.Hysteria.HopMin != 10 || hy.Hysteria.HopMax != 30 || hy.TLS.Fingerprint != "" || hy.TLS.Reality != nil || len(hy.Unknown) > 0 {
		t.Errorf("hysteria2: %+v %+v %v", hy.Hysteria, hy.TLS, hy.Unknown)
	}
}
