package linkparse

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	"nautilus/internal/proto"
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
		{"trojan://pass@t.example.com:443?sni=t.example.com&type=ws&host=t.example.com&path=%2Fws&allowInsecure=1#trojan", "trojan",
			proto.Spec{Type: "trojan", Server: "t.example.com", Port: 443, UDP: true, Password: "pass", TLS: &proto.TLS{SNI: "t.example.com", Insecure: true},
				Transport: proto.Transport{Network: "ws", Host: "t.example.com", Path: "/ws"}}},
		{"trojan-go://p%40ss@tg.example.com:443/?sni=cdn.example.com&type=ws&host=cdn.example.com&path=%2Fws&encryption=ss%3Baes-128-gcm%3Bsspass#TG", "TG",
			proto.Spec{Type: "trojan-go", Server: "tg.example.com", Port: 443, UDP: true, Password: "p@ss", TLS: &proto.TLS{SNI: "cdn.example.com"},
				Transport: proto.Transport{Network: "ws", Host: "cdn.example.com", Path: "/ws"}, TrojanGo: &proto.TrojanGo{SSMethod: "aes-128-gcm", SSPassword: "sspass"}}},
		{"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:pass")) + "@1.2.3.4:8388#ss", "ss",
			proto.Spec{Type: "ss", Server: "1.2.3.4", Port: 8388, UDP: true, Cipher: "aes-128-gcm", Password: "pass"}},
		{"ss://2022-blake3-aes-128-gcm:AAAAAAAAAAAAAAAAAAAAAA%3D%3D@1.2.3.4:8388#ss22", "ss22",
			proto.Spec{Type: "ss", Server: "1.2.3.4", Port: 8388, UDP: true, Cipher: "2022-blake3-aes-128-gcm", Password: "AAAAAAAAAAAAAAAAAAAAAA=="}},
		{"ss://" + b64("aes-256-gcm:p@ss@1.2.3.4:8389") + "#legacy", "legacy",
			proto.Spec{Type: "ss", Server: "1.2.3.4", Port: 8389, UDP: true, Cipher: "aes-256-gcm", Password: "p@ss"}},
		{"ss://" + b64("aes-128-gcm:x") + "@1.2.3.4:1/?plugin=obfs-local%3Bobfs%3Dhttp#p", "p",
			proto.Spec{Type: "ss", Server: "1.2.3.4", Port: 1, UDP: true, Cipher: "aes-128-gcm", Password: "x", Unknown: []string{"plugin: obfs-local"}}},
		{"hysteria2://auth@h.example.com:443?sni=h.example.com&obfs=salamander&obfs-password=o&insecure=1&up=50#hy2", "hy2",
			proto.Spec{Type: "hysteria2", Server: "h.example.com", Port: 443, UDP: true, Password: "auth", TLS: &proto.TLS{SNI: "h.example.com", Insecure: true},
				Hysteria: &proto.Hysteria{Obfs: "salamander", ObfsPassword: "o", Up: "50 mbps"}}},
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
		"https://example.com", "tuic://u:p@h:443", "vmess://not-base64!", "vless://u@h:notaport", "ss://bm9jb2xvbg@h:1",
	} {
		if _, _, err := Parse(link); err == nil {
			t.Errorf("Parse(%q) succeeded, want error", link)
		} else if strings.Contains(err.Error(), "panic") {
			t.Errorf("Parse(%q): %v", link, err)
		}
	}
}
