package proto

import (
	"reflect"
	"testing"

	"go.yaml.in/yaml/v3"
)

func decode(t *testing.T, src string) *Spec {
	t.Helper()
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(src), &n); err != nil {
		t.Fatal(err)
	}
	return FromClash(n.Content[0])
}

func TestFromClash(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want Spec
	}{
		{"vless reality vision", `{ name: a, type: vless, server: s.example, port: "443", uuid: u, flow: xtls-rprx-vision,
			tls: true, servername: www.example.com, client-fingerprint: chrome, udp: true,
			reality-opts: { public-key: pk, short-id: "01" } }`,
			Spec{Type: "vless", Server: "s.example", Port: 443, UDP: true, UUID: "u", Flow: "xtls-rprx-vision",
				TLS: &TLS{SNI: "www.example.com", Fingerprint: "chrome", Reality: &Reality{PublicKey: "pk", ShortID: "01"}}}},
		{"vmess ws early data", `{ name: a, type: vmess, server: s, port: 443, uuid: u, alterId: 0, cipher: auto, tls: true,
			skip-cert-verify: true, network: ws, grpc-opts: { grpc-service-name: unused },
			ws-opts: { path: /ray, headers: { Host: cdn.example }, max-early-data: 2048, early-data-header-name: Sec-WebSocket-Protocol } }`,
			Spec{Type: "vmess", Server: "s", Port: 443, UUID: "u", Cipher: "auto", TLS: &TLS{Insecure: true},
				Transport: Transport{Network: "ws", Path: "/ray", Host: "cdn.example", Headers: map[string]string{}, EarlyData: 2048, EarlyDataHeader: "Sec-WebSocket-Protocol"}}},
		{"trojan httpupgrade", `{ name: a, type: trojan, server: s, port: 443, password: p, sni: t.example, alpn: [h2, http/1.1],
			network: ws, ws-opts: { path: /up, v2ray-http-upgrade: true } }`,
			Spec{Type: "trojan", Server: "s", Port: 443, Password: "p", TLS: &TLS{SNI: "t.example", ALPN: []string{"h2", "http/1.1"}},
				Transport: Transport{Network: "httpupgrade", Path: "/up"}}},
		{"hysteria2", `{ name: a, type: hysteria2, server: s, port: 443, password: p, up: 50, down: "200 Mbps",
			obfs: salamander, obfs-password: o, ports: 20000-30000, hop-interval: 30, sni: h.example, fingerprint: AA:BB }`,
			Spec{Type: "hysteria2", Server: "s", Port: 443, UDP: true, Password: "p", TLS: &TLS{SNI: "h.example", PinSHA256: "AA:BB"},
				Hysteria: &Hysteria{Obfs: "salamander", ObfsPassword: "o", Up: "50 mbps", Down: "200 mbps", Ports: "20000-30000", HopInterval: 30}}},
		{"wireguard", `{ name: a, type: wireguard, server: 1.2.3.4, port: 51820, ip: 172.16.0.2, ipv6: "fd01::2",
			private-key: k, public-key: pk, reserved: "AQID", mtu: 1280 }`,
			Spec{Type: "wireguard", Server: "1.2.3.4", Port: 51820, UDP: true, WireGuard: &WireGuard{
				PrivateKey: "k", MTU: 1280, Address: []string{"172.16.0.2/32", "fd01::2/128"},
				Peers: []WireGuardPeer{{Server: "1.2.3.4", Port: 51820, PublicKey: "pk", Reserved: []int{1, 2, 3}}}}}},
		{"sockopt and unknowns", `{ name: a, type: ss, server: s, port: 1, cipher: aes-128-gcm, password: p, tfo: true,
			interface-name: eth0, routing-mark: 255, plugin: obfs, plugin-opts: { mode: tls }, smux: { enabled: true } }`,
			Spec{Type: "ss", Server: "s", Port: 1, Cipher: "aes-128-gcm", Password: "p",
				Sockopt: Sockopt{TFO: true, Interface: "eth0", Mark: 255}, Unknown: []string{"plugin: obfs", "smux"}}},
		{"unsupported protocol", `{ name: a, type: tuic, server: s, port: 1, uuid: u, congestion-controller: bbr }`,
			Spec{Type: "tuic", Server: "s", Port: 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decode(t, tt.src)
			if !reflect.DeepEqual(*got, tt.want) {
				t.Errorf("FromClash:\n got  %+v\n want %+v", *got, tt.want)
			}
		})
	}
}

func TestNestedUnknownFields(t *testing.T) {
	s := decode(t, `{ name: a, type: vless, server: s, port: 1, uuid: u, network: grpc,
		grpc-opts: { grpc-service-name: svc, ping-interval: 5 }, reality-opts: { public-key: k, future: 1 } }`)
	want := []string{"grpc-opts.ping-interval", "reality-opts.future"}
	if !reflect.DeepEqual(s.Unknown, want) {
		t.Errorf("Unknown = %q, want %q", s.Unknown, want)
	}
	if s.Transport.ServiceName != "svc" || s.TLS == nil || s.TLS.Reality == nil {
		t.Errorf("spec = %+v", s)
	}
}
