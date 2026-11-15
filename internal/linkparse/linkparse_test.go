package linkparse

import (
	"encoding/base64"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/xiongnemo/conch/internal/proto"
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestParse(t *testing.T) {
	vmessJSON := `{"v":"2","ps":"香港 01","add":"hk.example.com","port":"443","id":"u-1","aid":"0","scy":"auto",
		"net":"ws","type":"none","host":"cdn.example.com","path":"/ray?ed=2048","tls":"tls","sni":"hk.example.com","alpn":"h2,http/1.1","fp":"chrome"}`
	tests := []struct {
		link string
		name string
		want proto.Spec
	}{
		{"vmess://" + b64(vmessJSON), "香港 01", proto.Spec{Type: "vmess", Server: "hk.example.com", Port: 443, UDP: true, UUID: "u-1", Cipher: "auto",
			TLS:       &proto.TLS{SNI: "hk.example.com", ALPN: []string{"h2", "http/1.1"}, Fingerprint: "chrome"},
			Transport: proto.Transport{Network: "ws", Host: "cdn.example.com", Path: "/ray", EarlyData: 2048, EarlyDataHeader: "Sec-WebSocket-Protocol"}}},
		{"vmess://" + base64.RawURLEncoding.EncodeToString([]byte(`{"ps":"g","add":"1.2.3.4","port":8443,"id":"u","aid":0,"net":"grpc","path":"svc","tls":""}`)), "g",
			proto.Spec{Type: "vmess", Server: "1.2.3.4", Port: 8443, UDP: true, UUID: "u", Transport: proto.Transport{Network: "grpc", ServiceName: "svc"}}},
		{"vless://u-2@1.2.3.4:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=KEY&sid=6ba8&type=tcp&headerType=none#JP%2001",
			"JP 01", proto.Spec{Type: "vless", Server: "1.2.3.4", Port: 443, UDP: true, UUID: "u-2", Flow: "xtls-rprx-vision", Encryption: "none",
				TLS: &proto.TLS{SNI: "www.microsoft.com", Fingerprint: "chrome", Reality: &proto.Reality{PublicKey: "KEY", ShortID: "6ba8"}}}},
		{"vless://u-3@x.example.com:443?security=tls&sni=x.example.com&type=xhttp&path=%2Fxh&mode=auto&custom=1#xh", "xh",
			proto.Spec{Type: "vless", Server: "x.example.com", Port: 443, UDP: true, UUID: "u-3", TLS: &proto.TLS{SNI: "x.example.com"},
				Transport: proto.Transport{Network: "xhttp", Path: "/xh", Mode: "auto"}, Unknown: []string{"custom"}}},
		// xray's extra, in mihomo's names; downloads elsewhere.
		{"vless://u@x.example.com:443?security=tls&sni=x.example.com&type=xhttp&path=%2Fxh&extra=" + url.QueryEscape(`{"noGRPCHeader":true,"xPaddingBytes":"100-1000",`+
			`"xmux":{"maxConcurrency":"16-32"},"future":1,"downloadSettings":{"address":"d.example.com","port":8443,"security":"tls",`+
			`"tlsSettings":{"serverName":"d.example.com","fingerprint":"chrome"},"xhttpSettings":{"path":"/down"}}}`) + "#ex", "ex",
			proto.Spec{Type: "vless", Server: "x.example.com", Port: 443, UDP: true, UUID: "u", TLS: &proto.TLS{SNI: "x.example.com"},
				Transport: proto.Transport{Network: "xhttp", Path: "/xh",
					XHTTPExtra: map[string]any{"no-grpc-header": true, "x-padding-bytes": "100-1000", "reuse-settings": map[string]any{"max-concurrency": "16-32"}},
					Download:   &proto.XHTTPDownload{Server: "d.example.com", Port: 8443, Path: "/down", TLS: &proto.TLS{SNI: "d.example.com", Fingerprint: "chrome"}}},
				Unknown: []string{"extra.future"}}},
		{"trojan://pass@t.example.com:443?sni=t.example.com&type=ws&host=t.example.com&path=%2Fws&allowInsecure=1#trojan", "trojan",
			proto.Spec{Type: "trojan", Server: "t.example.com", Port: 443, UDP: true, Password: "pass", TLS: &proto.TLS{SNI: "t.example.com", Insecure: true},
				Transport: proto.Transport{Network: "ws", Host: "t.example.com", Path: "/ws"}}},
		{"trojan-go://p%40ss@tg.example.com:443/?sni=cdn.example.com&type=ws&host=cdn.example.com&path=%2Fws&encryption=ss%3Baes-128-gcm%3Bsspass#TG", "TG",
			proto.Spec{Type: "trojan-go", Server: "tg.example.com", Port: 443, UDP: true, Password: "p@ss", TLS: &proto.TLS{SNI: "cdn.example.com"},
				Transport: proto.Transport{Network: "ws", Host: "cdn.example.com", Path: "/ws"}, TrojanGo: &proto.TrojanGo{SSMethod: "aes-128-gcm", SSPassword: "sspass"}}},
		// ECH, verifying another name, early data in another header, packet encoding.
		{"vless://u@v.example.com:443?security=tls&sni=v.example.com&ech=ech.example.com%2Bhttps%3A%2F%2F1.1.1.1%2Fdns-query&vcn=real.example.com" +
			"&type=ws&path=%2Fw%3Fed%3D2048&eh=X-Early&packetEncoding=xudp&mode=multi#e", "e",
			proto.Spec{Type: "vless", Server: "v.example.com", Port: 443, UDP: true, UUID: "u", PacketEncoding: "xudp",
				TLS:       &proto.TLS{SNI: "v.example.com", VerifyName: "real.example.com", ECH: &proto.ECH{QueryServerName: "ech.example.com"}},
				Transport: proto.Transport{Network: "ws", Path: "/w", EarlyData: 2048, EarlyDataHeader: "X-Early"}, Unknown: []string{"mode"}}},
		{"trojan://p@t.example.com:443?type=grpc&serviceName=s&mode=multi&authority=a.example#g", "g",
			proto.Spec{Type: "trojan", Server: "t.example.com", Port: 443, UDP: true, Password: "p", TLS: &proto.TLS{},
				Transport: proto.Transport{Network: "grpc", ServiceName: "s"}, Unknown: []string{"mode=multi", "authority=a.example"}}},
		// What sing-box has and xray not.
		{"tuic://11111111-2222-3333-4444-555555555555:pw@t.example.com:443?congestion_control=bbr&udp_relay_mode=quic&sni=t.example.com&alpn=h3&odd=1#tuic", "tuic",
			proto.Spec{Type: "tuic", Server: "t.example.com", Port: 443, UDP: true, UUID: "11111111-2222-3333-4444-555555555555", Password: "pw",
				TLS: &proto.TLS{SNI: "t.example.com", ALPN: []string{"h3"}}, TUIC: &proto.TUIC{Congestion: "bbr", UDPRelayMode: "quic", Heartbeat: 10000}, Unknown: []string{"odd"}}},
		{"hysteria://h.example.com:443?auth=a&peer=h.example.com&obfs=o&upmbps=30&downmbps=200&protocol=udp#hy1", "hy1",
			proto.Spec{Type: "hysteria", Server: "h.example.com", Port: 443, UDP: true, Password: "a", TLS: &proto.TLS{SNI: "h.example.com", ALPN: []string{"hysteria"}},
				Hysteria: &proto.Hysteria{ObfsPassword: "o", Protocol: "udp", Up: 30_000_000, Down: 200_000_000, HopMin: 10, HopMax: 10}}},
		{"anytls://pw@a.example.com?sni=a.example.com&insecure=1#at", "at",
			proto.Spec{Type: "anytls", Server: "a.example.com", Port: 443, UDP: true, Password: "pw", TLS: &proto.TLS{SNI: "a.example.com", Insecure: true}, AnyTLS: &proto.AnyTLS{}}},
		// A password with ":" in it; no port means 443.
		{"trojan://pa:ss@t.example.com?sni=t.example.com#colon", "colon",
			proto.Spec{Type: "trojan", Server: "t.example.com", Port: 443, UDP: true, Password: "pa:ss", TLS: &proto.TLS{SNI: "t.example.com"}}},
		{"ss://" + b64("aes-128-gcm:x") + "@1.2.3.4:1/?uot=1#uot", "uot",
			proto.Spec{Type: "ss", Server: "1.2.3.4", Port: 1, UDP: true, Cipher: "aes-128-gcm", Password: "x", UDPOverTCP: true}},
		// Bytes are bytes; an address the format cannot hold is said.
		{"hy2://a@h.example.com?up=12%20MBps&down=1%20Gbps#bw", "bw",
			proto.Spec{Type: "hysteria2", Server: "h.example.com", Port: 443, UDP: true, Password: "a", TLS: &proto.TLS{},
				Hysteria: &proto.Hysteria{Up: 96_000_000, Down: 1_000_000_000}}},
		{"wireguard://K@1.2.3.4:51820?publickey=P&address=10.0.0.2,10.0.0.3#wg2", "wg2",
			proto.Spec{Type: "wireguard", Server: "1.2.3.4", Port: 51820, UDP: true, Unknown: []string{"address=10.0.0.3/32（每类地址只能有一个）"},
				WireGuard: &proto.WireGuard{PrivateKey: "K", Address: []string{"10.0.0.2/32"}, Peers: []proto.WireGuardPeer{{Server: "1.2.3.4", Port: 51820, PublicKey: "P"}}}}},
		// trojan-go's own form of the ss layer, and none.
		{"trojan-go://pw@tg.example.com:443/?encryption=ss%3BAES-256-GCM%3Ass%3Apass#TG2", "TG2",
			proto.Spec{Type: "trojan-go", Server: "tg.example.com", Port: 443, UDP: true, Password: "pw", TLS: &proto.TLS{},
				TrojanGo: &proto.TrojanGo{SSMethod: "AES-256-GCM", SSPassword: "ss:pass"}}},
		{"trojan-go://pw@tg.example.com:443/?encryption=none#TG3", "TG3",
			proto.Spec{Type: "trojan-go", Server: "tg.example.com", Port: 443, UDP: true, Password: "pw", TLS: &proto.TLS{}}},
		{"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:pass")) + "@1.2.3.4:8388#ss", "ss",
			proto.Spec{Type: "ss", Server: "1.2.3.4", Port: 8388, UDP: true, Cipher: "aes-128-gcm", Password: "pass"}},
		{"ss://2022-blake3-aes-128-gcm:AAAAAAAAAAAAAAAAAAAAAA%3D%3D@1.2.3.4:8388#ss22", "ss22",
			proto.Spec{Type: "ss", Server: "1.2.3.4", Port: 8388, UDP: true, Cipher: "2022-blake3-aes-128-gcm", Password: "AAAAAAAAAAAAAAAAAAAAAA=="}},
		{"ss://" + b64("aes-256-gcm:p@ss@1.2.3.4:8389") + "#legacy", "legacy",
			proto.Spec{Type: "ss", Server: "1.2.3.4", Port: 8389, UDP: true, Cipher: "aes-256-gcm", Password: "p@ss"}},
		{"ss://" + b64("aes-128-gcm:x") + "@1.2.3.4:1/?plugin=obfs-local%3Bobfs%3Dhttp#p", "p",
			proto.Spec{Type: "ss", Server: "1.2.3.4", Port: 1, UDP: true, Cipher: "aes-128-gcm", Password: "x", Plugin: &proto.Plugin{Name: "obfs", Mode: "http", Host: "bing.com"}}},
		{"ss://" + b64("aes-128-gcm:x") + "@1.2.3.4:1/?plugin=v2ray-plugin%3Btls%3Bhost%3Dcdn.example%3Bpath%3D%2Fv%3Bmux%3D0#v", "v",
			proto.Spec{Type: "ss", Server: "1.2.3.4", Port: 1, UDP: true, Cipher: "aes-128-gcm", Password: "x",
				Plugin: &proto.Plugin{Name: "v2ray-plugin", Mode: "websocket", Host: "cdn.example", Path: "/v", TLS: &proto.TLS{SNI: "cdn.example"}}}},
		{"ss://" + b64("aes-128-gcm:x") + "@1.2.3.4:1/?plugin=kcptun%3Bkey%3Dk#k", "k",
			proto.Spec{Type: "ss", Server: "1.2.3.4", Port: 1, UDP: true, Cipher: "aes-128-gcm", Password: "x", Unknown: []string{"plugin: kcptun"}}},
		{"hysteria2://auth@h.example.com:443?sni=h.example.com&obfs=salamander&obfs-password=o&insecure=1&up=50#hy2", "hy2",
			proto.Spec{Type: "hysteria2", Server: "h.example.com", Port: 443, UDP: true, Password: "auth", TLS: &proto.TLS{SNI: "h.example.com", Insecure: true},
				Hysteria: &proto.Hysteria{Obfs: "salamander", ObfsPassword: "o", Up: 50_000_000}}},
		{"hy2://auth@[2001:db8::1]:443,20000-30000/?sni=x#hop", "hop",
			proto.Spec{Type: "hysteria2", Server: "2001:db8::1", Port: 443, UDP: true, Password: "auth", TLS: &proto.TLS{SNI: "x"},
				Hysteria: &proto.Hysteria{Ports: "443,20000-30000"}}},
		{"socks://" + b64("user:pass") + "@1.2.3.4:1080#s", "s",
			proto.Spec{Type: "socks5", Server: "1.2.3.4", Port: 1080, UDP: true, Username: "user", Password: "pass"}},
		{"wireguard://KEY%3D@1.2.3.4:51820?publickey=PUB%3D&address=10.0.0.2%2F32,fd00::2&mtu=1280&reserved=1,2,3#wg", "wg",
			proto.Spec{Type: "wireguard", Server: "1.2.3.4", Port: 51820, UDP: true, WireGuard: &proto.WireGuard{PrivateKey: "KEY=", MTU: 1280,
				Address: []string{"10.0.0.2/32", "fd00::2/128"}, Peers: []proto.WireGuardPeer{{Server: "1.2.3.4", Port: 51820, PublicKey: "PUB=", Reserved: []int{1, 2, 3}}}}}},
	}
	for _, tt := range tests {
		name, got, err := Parse(tt.link)
		if err != nil {
			t.Errorf("Parse(%.40s…): %v", tt.link, err)
			continue
		}
		if name != tt.name || !reflect.DeepEqual(*got, tt.want) {
			t.Errorf("Parse(%.60s…):\n got  %q %+v\n want %q %+v", tt.link, name, *got, tt.name, tt.want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, link := range []string{
		"https://example.com", "mieru://u:p@h:443", "vless://u@h.example.com:443?type=kcp&security=tls", "vmess://not-base64!", "vless://u@h:notaport", "ss://bm9jb2xvbg@h:1",
	} {
		if _, _, err := Parse(link); err == nil {
			t.Errorf("Parse(%q) succeeded, want error", link)
		} else if strings.Contains(err.Error(), "panic") {
			t.Errorf("Parse(%q): %v", link, err)
		}
	}
}
