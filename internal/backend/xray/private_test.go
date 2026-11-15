package xray

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xiongnemo/conch/internal/backend"
	"github.com/xiongnemo/conch/internal/backend/backendtest"
)

func TestRequiresEncryption(t *testing.T) {
	for server, want := range map[string]bool{
		"203.0.114.1": true, "example.com": true, "1.1.1.1": true, "2606:4700::1": true,
		"127.0.0.1": false, "10.1.2.3": false, "192.168.1.1": false, "100.64.0.1": false, "[::1]": false,
		"fd00::1": false, "nas.lan": false, "router.local": false, "localhost": false, "nas": false, "box.home.arpa": false,
	} {
		if got := requiresEncryption(server); got != want {
			t.Errorf("requiresEncryption(%q) = %v, want %v", server, got, want)
		}
	}
}

// What xray v26.11.9 no longer takes is an error that names the node, or
// a warning where the node still works.
func TestNodesXrayNoLongerTakes(t *testing.T) {
	for _, c := range []struct {
		node, want string
		err        bool
	}{
		{`{ name: v, type: vless, server: 203.0.114.1, port: 80, uuid: 11111111-2222-3333-4444-555555555555 }`, "xray 不允许 VLESS 不加密", true},
		{`{ name: v, type: vless, server: 10.0.0.2, port: 80, uuid: 11111111-2222-3333-4444-555555555555 }`, "", false},
		{`{ name: v, type: vless, server: 203.0.114.1, port: 443, uuid: 11111111-2222-3333-4444-555555555555, tls: true, servername: a.example }`, "", false},
		{`{ name: s, type: ss, server: 203.0.114.1, port: 8388, cipher: none, password: p }`, "xray 不支持 shadowsocks 加密方式", true},
		{`{ name: s, type: ss, server: 203.0.114.1, port: 8388, cipher: aes-128-gcm, password: p, udp-over-tcp: true }`, "UDP over TCP", false},
		{`{ name: m, type: vmess, server: 203.0.114.1, port: 443, uuid: 11111111-2222-3333-4444-555555555555, alterId: 0, cipher: none, tls: true }`, "VMess 的 none 加密，改用 auto", false},
		{`{ name: h, type: hysteria2, server: 203.0.114.1, port: 443, password: p, ports: "20000:30000", hop-interval: 2 }`, "hop-interval 2 改为 5", false},
	} {
		dir := t.TempDir()
		profile := filepath.Join(dir, "profile.yaml")
		os.WriteFile(profile, []byte("nodes:\n  - "+c.node+"\nroutes: { default: "+strings.SplitN(strings.TrimPrefix(c.node, "{ name: "), ",", 2)[0]+" }\n"), 0o644)
		art, d := backendtest.Build(t, Backend{}, profile, backend.Options{})
		text := ""
		for _, x := range d {
			text += x.String() + "\n"
		}
		if c.err != (art == nil) || !strings.Contains(text, c.want) {
			t.Errorf("%s:\nconfig made: %v\n%s", c.node, art != nil, text)
		}
		if strings.Contains(c.node, "hysteria2") && art != nil && !strings.Contains(string(art.Config), `"remotePorts": "20000-30000"`) {
			t.Errorf("port range not in xray's form:\n%s", art.Config)
		}
	}
}
