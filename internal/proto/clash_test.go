package proto

import (
	"reflect"
	"strings"
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
				Transport: Transport{Network: "ws", Path: "/ray", Host: "cdn.example", EarlyData: 2048, EarlyDataHeader: "Sec-WebSocket-Protocol"}}},
		{"trojan httpupgrade", `{ name: a, type: trojan, server: s, port: 443, password: p, sni: t.example, alpn: [h2, http/1.1],
			network: ws, ws-opts: { path: /up, v2ray-http-upgrade: true } }`,
			Spec{Type: "trojan", Server: "s", Port: 443, Password: "p", TLS: &TLS{SNI: "t.example", ALPN: []string{"h2", "http/1.1"}},
				Transport: Transport{Network: "httpupgrade", Path: "/up"}}},
		{"hysteria2", `{ name: a, type: hysteria2, server: s, port: 443, password: p, up: 50, down: "200 Mbps",
			obfs: salamander, obfs-password: o, ports: 20000-30000, hop-interval: 30, sni: h.example, fingerprint: AA:BB }`,
			Spec{Type: "hysteria2", Server: "s", Port: 443, UDP: true, Password: "p", TLS: &TLS{SNI: "h.example", PinSHA256: "AA:BB"},
				Hysteria: &Hysteria{Obfs: "salamander", ObfsPassword: "o", Up: 50_000_000, Down: 200_000_000, Ports: "20000-30000", HopMin: 30, HopMax: 30}}},
		{"wireguard", `{ name: a, type: wireguard, server: 1.2.3.4, port: 51820, ip: 172.16.0.2, ipv6: "fd01::2",
			private-key: k, public-key: pk, reserved: "AQID", mtu: 1280 }`,
			Spec{Type: "wireguard", Server: "1.2.3.4", Port: 51820, UDP: true, WireGuard: &WireGuard{
				PrivateKey: "k", MTU: 1280, Address: []string{"172.16.0.2/32", "fd01::2/128"},
				Peers: []WireGuardPeer{{Server: "1.2.3.4", Port: 51820, PublicKey: "pk", Reserved: []int{1, 2, 3}}}}}},
		{"sockopt and unknowns", `{ name: a, type: ss, server: s, port: 1, cipher: aes-128-gcm, password: p, tfo: true,
			interface-name: eth0, routing-mark: 255, plugin: kcptun, plugin-opts: { key: k }, smux: { enabled: true } }`,
			Spec{Type: "ss", Server: "s", Port: 1, Cipher: "aes-128-gcm", Password: "p",
				Sockopt: Sockopt{TFO: true, Interface: "eth0", Mark: 255}, Mux: &Mux{}, Plugin: &Plugin{Name: "kcptun"}}},
		{"unsupported protocol", `{ name: a, type: mieru, server: s, port: 1, username: u, transport: TCP }`,
			Spec{Type: "mieru", Server: "s", Port: 1}},
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
	s := decode(t, `{ name: a, type: vless, server: s, port: 1, uuid: u, network: grpc, tls: true,
		grpc-opts: { grpc-service-name: svc, max-streams: 5 }, reality-opts: { public-key: k, future: 1 } }`)
	want := []string{"grpc-opts.max-streams", "reality-opts.future"}
	if !reflect.DeepEqual(s.Unknown, want) {
		t.Errorf("Unknown = %q, want %q", s.Unknown, want)
	}
	if s.Transport.ServiceName != "svc" || s.TLS == nil || s.TLS.Reality == nil {
		t.Errorf("spec = %+v", s)
	}
	// Without tls, mihomo takes REALITY's options for nothing.
	if s := decode(t, `{ name: a, type: vless, server: s, port: 1, uuid: u, reality-opts: { public-key: k } }`); s.TLS != nil {
		t.Errorf("REALITY without tls: %+v", s.TLS)
	}
}

// ToClash must be the inverse of FromClash for everything a Spec holds.
func TestClashRoundTrip(t *testing.T) {
	specs := []*Spec{
		{Type: "ss", Server: "s", Port: 1, UDP: true, Cipher: "2022-blake3-aes-128-gcm", Password: "p", UDPOverTCP: true, UoTVersion: 1},
		{Type: "ss", Server: "s", Port: 1, Cipher: "aes-128-gcm", Password: "p", Plugin: &Plugin{Name: "obfs", Mode: "tls", Host: "bing.com"}},
		{Type: "ss", Server: "s", Port: 1, Cipher: "aes-128-gcm", Password: "p", Plugin: &Plugin{Name: "v2ray-plugin", Mode: "websocket", Host: "cdn.example",
			Path: "/v", Headers: map[string]string{"X": "y"}, TLS: &TLS{SNI: "cdn.example", Insecure: true}}},
		{Type: "ss", Server: "s", Port: 1, Cipher: "2022-blake3-aes-128-gcm", Password: "p", Plugin: &Plugin{Name: "shadow-tls", Host: "www.example.com",
			Password: "st", Version: 3, TLS: &TLS{SNI: "www.example.com", ALPN: []string{"h2", "http/1.1"}, Fingerprint: "chrome"}}},
		{Type: "ss", Server: "s", Port: 1, Cipher: "aes-128-gcm", Password: "p", UDPOverTCP: true, UoTVersion: 2,
			Mux: &Mux{Protocol: "h2mux", MaxConnections: 4, Padding: true, BrutalUp: 50_000_000, BrutalDown: 100_000_000}},
		{Type: "vmess", Server: "s", Port: 443, UUID: "u", Cipher: "auto", GlobalPadding: true, AuthenticatedLength: true, PacketEncoding: "packetaddr",
			TLS:       &TLS{SNI: "a", VerifyName: "real.example", Certificate: "/c.pem", PrivateKey: "/k.pem", ECH: &ECH{QueryServerName: "q.example"}},
			Transport: Transport{Network: "grpc", ServiceName: "s", UserAgent: "ua", PingInterval: 15}},
		{Type: "vmess", Server: "s", Port: 443, UUID: "u", Cipher: "auto", TLS: &TLS{SNI: "a", ALPN: []string{"h2"}, Insecure: true},
			Transport: Transport{Network: "ws", Path: "/p", Host: "h", Headers: map[string]string{"X": "y"}, EarlyData: 2048, EarlyDataHeader: "Sec-WebSocket-Protocol"}},
		{Type: "vless", Server: "s", Port: 443, UDP: true, UUID: "u", Flow: "xtls-rprx-vision", Encryption: "mlkem768x25519plus.native.0rtt.x",
			TLS: &TLS{SNI: "a", Fingerprint: "chrome", Reality: &Reality{PublicKey: "k", ShortID: "01", SpiderX: "/"}}},
		{Type: "vless", Server: "s", Port: 443, UUID: "u", TLS: &TLS{SNI: "a"}, Transport: Transport{Network: "xhttp", Path: "/x", Host: "h", Mode: "packet-up"}},
		{Type: "vless", Server: "s", Port: 443, UUID: "u", TLS: &TLS{SNI: "a"}, Transport: Transport{Network: "xhttp", Path: "/x", Mode: "packet-up",
			XHTTPExtra: map[string]any{"no-grpc-header": true, "x-padding-bytes": "100-1000", "reuse-settings": map[string]any{"max-concurrency": "16-32"}},
			Download:   &XHTTPDownload{Server: "d.example", Port: 443, Path: "/d", TLS: &TLS{SNI: "d.example", Fingerprint: "chrome"}}}},
		{Type: "trojan", Server: "s", Port: 443, Password: "p", TLS: &TLS{SNI: "a", PinSHA256: "abcd"}, Transport: Transport{Network: "grpc", ServiceName: "svc"}},
		{Type: "trojan", Server: "s", Port: 443, Password: "p", TLS: &TLS{}, Transport: Transport{Network: "httpupgrade", Path: "/u", Host: "h"}},
		{Type: "socks5", Server: "s", Port: 1080, Username: "u", Password: "p", TLS: &TLS{Insecure: true}},
		{Type: "http", Server: "s", Port: 8080, Username: "u", Password: "p", Headers: map[string]string{"User-Agent": "x"}},
		{Type: "hysteria2", Server: "s", Port: 443, UDP: true, Password: "p", TLS: &TLS{SNI: "a"},
			Hysteria: &Hysteria{Obfs: "salamander", ObfsPassword: "o", Up: 50_000_000, Down: 1_000_000_000, Ports: "1000-2000", HopMin: 30, HopMax: 30}},
		{Type: "hysteria2", Server: "s", Port: 443, UDP: true, Password: "p", TLS: &TLS{ECH: &ECH{Config: "AEX+"}},
			Hysteria: &Hysteria{Obfs: "gecko", ObfsPassword: "g", ObfsMinPacket: 600, Ports: "443,1000-2000", HopMin: 10, HopMax: 30,
				BBRProfile: "aggressive", MaxStreamWindow: 8388608, MaxConnWindow: 20971520}},
		{Type: "wireguard", Server: "1.2.3.4", Port: 51820, UDP: true, WireGuard: &WireGuard{PrivateKey: "k", MTU: 1280,
			Address: []string{"10.0.0.2/32", "fd00::2/128"}, Keepalive: 25, Workers: 2, DNS: []string{"1.1.1.1"}, RemoteDNS: true, Amnezia: map[string]any{"jc": 3, "jmin": 40}, Peers: []WireGuardPeer{{Server: "1.2.3.4", Port: 51820, PublicKey: "pk", Reserved: []int{1, 2, 3}}}}},
		{Type: "wireguard", Server: "1.2.3.4", Port: 51820, UDP: true, WireGuard: &WireGuard{PrivateKey: "k", Address: []string{"10.0.0.0/24"},
			Peers: []WireGuardPeer{{Server: "a", Port: 1, PublicKey: "p1", AllowedIPs: []string{"0.0.0.0/0"}}, {Server: "b", Port: 2, PublicKey: "p2"}}}},
		{Type: "vless", Server: "s", Port: 1, UUID: "u", Sockopt: Sockopt{TFO: true, MPTCP: true, Interface: "eth0", Mark: 7, IPVersion: "ipv6"}},
		{Type: "tuic", Server: "s", Port: 443, UDP: true, UUID: "u", Password: "p", TLS: &TLS{SNI: "a", ALPN: []string{"h3"}, DisableSNI: true},
			TUIC: &TUIC{Congestion: "bbr", UDPRelayMode: "quic", ReduceRTT: true, Heartbeat: 10000}},
		{Type: "hysteria", Server: "s", Port: 443, UDP: true, Password: "a", TLS: &TLS{SNI: "a", ALPN: []string{"hysteria"}},
			Hysteria: &Hysteria{ObfsPassword: "o", Protocol: "udp", Up: 10_000_000, Down: 50_000_000, Ports: "1000-2000", HopMin: 10, HopMax: 10, InitStreamWindow: 15728640}},
		{Type: "anytls", Server: "s", Port: 443, UDP: true, Password: "p", TLS: &TLS{SNI: "a", Fingerprint: "chrome"}, AnyTLS: &AnyTLS{IdleCheck: 30, IdleTimeout: 30, MinIdle: 1}},
		{Type: "ssh", Server: "s", Port: 22, Username: "u", Password: "p", SSH: &SSH{PrivateKey: "/k", HostKeys: []string{"ssh-ed25519 AAAA"}}},
		{Type: "direct", Server: "", Port: 0, Sockopt: Sockopt{Interface: "eth1"}},
	}
	for _, want := range specs {
		got := FromClash(ToClash("n", want))
		if !reflect.DeepEqual(got, want) {
			out, _ := yaml.Marshal(ToClash("n", want))
			t.Errorf("round trip changed the spec:\n got  %+v\n want %+v\nclash:\n%s", *got, *want, out)
		}
	}
	// mihomo relays a WireGuard node's UDP only when told to.
	wg, _ := yaml.Marshal(ToClash("n", &Spec{Type: "wireguard", Server: "s", Port: 1, UDP: true, WireGuard: &WireGuard{PrivateKey: "k"}}))
	if !strings.Contains(string(wg), "udp: true") {
		t.Errorf("a WireGuard node without UDP for mihomo:\n%s", wg)
	}
}

// Bandwidth as each kernel would read it, in bits per second.
func TestBandwidth(t *testing.T) {
	for in, want := range map[string]uint64{
		"100": 100e6, "1.5": 1.5e6, "100 Mbps": 100e6, "100Mbps": 100e6, "100 mbps": 100e6,
		"12 MBps": 96e6, "1 Gbps": 1e9, "500 Kbps": 500e3, "800 bps": 800, "1 gbps": 1e9, "2.5 mbps": 2.5e6,
	} {
		if got, ok := ParseBandwidth(in); !ok || got != want {
			t.Errorf("%q = %d, %v; want %d", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "fast", "-1", "0", "10 Mbit"} {
		if _, ok := ParseBandwidth(in); ok {
			t.Errorf("%q read", in)
		}
	}
	for bits, want := range map[uint64]string{100e6: "100 Mbps", 96e6: "96 Mbps", 1e9: "1 Gbps", 1.5e6: "1500 Kbps", 800: "800 bps"} {
		if got := FormatBandwidth(bits); got != want {
			t.Errorf("%d = %q, want %q", bits, got, want)
		}
	}
}

// Of AmneziaWG, junk before the handshake is what plain WireGuard servers
// take too; WireGuard's own header values change nothing.
func TestAmneziaJunk(t *testing.T) {
	for opts, want := range map[string]bool{
		"{ jc: 3, jmin: 40, jmax: 70 }":                             true,
		"{ jc: 3, jmin: 40, jmax: 70, h1: 1, h2: 2, h3: 3, h4: 4 }": true,
		"{ jc: 3, s1: 10 }":                                         false,
		"{ jc: 3, h1: 1234 }":                                       false,
		"{ i1: \"<b 0xf6>\" }":                                      false,
	} {
		s := decode(t, "{ name: a, type: wireguard, server: s, port: 1, private-key: k, public-key: p, amnezia-wg-option: "+opts+" }")
		if _, _, _, ok := s.WireGuard.AmneziaJunk(); ok != want {
			t.Errorf("%s: %v, want %v", opts, ok, want)
		}
	}
}
