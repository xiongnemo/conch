package sidecar

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/xiongnemo/conch/internal/backend"
	"github.com/xiongnemo/conch/internal/backend/mihomo"
	"github.com/xiongnemo/conch/internal/backend/xray"
	"github.com/xiongnemo/conch/internal/certpin"
	"github.com/xiongnemo/conch/internal/compile"
	"github.com/xiongnemo/conch/internal/diag"
	"github.com/xiongnemo/conch/internal/model"
)

const profile = `
nodes:
  - { name: hop1, type: socks5, server: 192.0.2.1, port: 1080 }
  - name: tg
    type: trojan-go
    server: tg.example.com
    port: 443
    password: secret
    sni: cdn.example.com
    skip-cert-verify: true
    network: ws
    ws-opts: { path: /ws, headers: { Host: cdn.example.com } }
    ss-opts: { enabled: true, method: aes-128-gcm, password: sspass }
    mux: true
chains:
  经中转: [hop1, tg]
routes:
  default: tg
  entries:
    example.org: 经中转
`

func plan(t *testing.T) (*compile.Result, []Sidecar, []backend.Forward) {
	t.Helper()
	p, err := model.Parse([]byte(profile), "profile.yaml")
	if err != nil {
		t.Fatal(err)
	}
	res := compile.Compile(p)
	if err := res.Diags.Err(); err != nil {
		t.Fatal(err)
	}
	enc, cars, fwd, _, err := Plan(res, map[string]Ports{"tg": {Local: 20001}, "经中转": {Local: 20002, Forward: 20003}}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	// The compiled result itself is untouched: UIs still see the node.
	for _, p := range res.Proxies {
		if p.Name == "tg" && p.Node.View.Type != "trojan-go" {
			t.Error("Plan changed the compiled result")
		}
	}
	return enc, cars, fwd
}

func TestPlan(t *testing.T) {
	enc, cars, fwd := plan(t)
	if len(cars) != 2 || len(fwd) != 1 || fwd[0].Port != 20003 || fwd[0].Via != "hop1" {
		t.Fatalf("sidecars %+v, forwards %+v", cars, fwd)
	}
	for _, p := range enc.Proxies {
		if p.Name == "经中转" && (p.Upstream != "" || p.Node.View.Type != "socks5" || p.Node.View.Port != 20002) {
			t.Errorf("chain exit for the kernel = %+v %+v", p, p.Node.View)
		}
	}
	var c trojanGoClient
	json.Unmarshal(cars[1].Config, &c)
	if c.LocalPort != 20002 || c.RemoteAddr != "tg.example.com" || c.Password[0] != "secret" || c.SSL.Verify || c.SSL.SNI != "cdn.example.com" ||
		!c.Websocket.Enabled || c.Websocket.Path != "/ws" || c.Websocket.Host != "cdn.example.com" ||
		!c.Shadowsocks.Enabled || c.Shadowsocks.Method != "AES-128-GCM" || !c.Mux.Enabled ||
		!c.ForwardProxy.Enabled || c.ForwardProxy.ProxyPort != 20003 {
		t.Errorf("trojan-go config:\n%s", cars[1].Config)
	}
	json.Unmarshal(cars[0].Config, &c)
	if c.ForwardProxy.Enabled {
		t.Error("a sidecar that is not in a chain must dial directly")
	}
	if _, _, _, _, err := Plan(enc, nil, nil, false); err != nil {
		t.Errorf("planning a planned result again: %v", err)
	}
}

// A certificate pin is checked whatever skip-cert-verify says: by trusting
// the pinned certificate alone once it is learned, as usual until then.
// It is not the uTLS fingerprint, which client-fingerprint is.
func TestTrojanGoPins(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	n := model.NewNode(mapping(t, `{ name: tg, type: trojan-go, server: tg.example.com, port: 443, password: p, skip-cert-verify: true,
  fingerprint: "`+pin+`", client-fingerprint: chrome }`), diag.Pos{})
	learned := func(p string) (certpin.Pin, bool) {
		return certpin.Pin{CA: "-----BEGIN CERTIFICATE-----\n...\n"}, p == pin
	}
	for _, c := range []struct {
		certs    certpin.Lookup
		wantCert bool
	}{{nil, false}, {func(string) (certpin.Pin, bool) { return certpin.Pin{}, false }, false}, {learned, true}} {
		b, cert, _, err := TrojanGoConfig(n, Ports{Local: 20001}, "x.pem", c.certs)
		var cfg trojanGoClient
		json.Unmarshal(b, &cfg)
		if err != nil || !cfg.SSL.Verify || cfg.SSL.Fingerprint != "chrome" || (cfg.SSL.Cert == "x.pem") != c.wantCert || (cert != nil) != c.wantCert {
			t.Errorf("learned %v: %v\n%s\ncert %q", c.wantCert, err, b, cert)
		}
	}
	target, ok := PinTarget(n)
	if !ok || target.Pin != pin || target.Address != "tg.example.com:443" || target.ServerName != "tg.example.com" {
		t.Errorf("pin target %+v", target)
	}
}

func mapping(t *testing.T, text string) *yaml.Node {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Content[0]
}

// Both kernels accept the configs with sidecars in them.
func TestKernelsAcceptSidecars(t *testing.T) {
	enc, _, fwd := plan(t)
	for name, b := range map[string]backend.Router{"mihomo": mihomo.Backend{}, "xray": xray.Backend{}} {
		art, d := b.Encode(enc, backend.Options{Forwards: fwd})
		if art == nil {
			t.Fatalf("%s: %v", name, d.Err())
		}
		bin := os.Getenv("CONCH_" + strings.ToUpper(name))
		if bin == "" {
			continue
		}
		dir := t.TempDir()
		var cmd *exec.Cmd
		if name == "mihomo" {
			path := filepath.Join(dir, "config.yaml")
			os.WriteFile(path, art.Config, 0o600)
			cmd = exec.Command(bin, "-t", "-d", dir, "-f", path)
		} else {
			path := filepath.Join(dir, "config.json")
			os.WriteFile(path, art.Config, 0o600)
			cmd = exec.Command(bin, "run", "-test", "-c", path)
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s rejected the config: %v\n%s\n%s", name, err, out, art.Config)
		}
	}
}

// A node in trojan-go's terms: what it has, the nearest of what it lacks
// (said), and errors for what would silently be another transport.
func TestTrojanGoTranslation(t *testing.T) {
	for _, c := range []struct {
		node, said, err string
		check           func(trojanGoClient) bool
	}{
		{node: `{ name: a, type: trojan-go, server: s, port: 443, password: p, client-fingerprint: safari }`, said: "改用 ios",
			check: func(c trojanGoClient) bool { return c.SSL.Fingerprint == "ios" }},
		{node: `{ name: a, type: trojan-go, server: s, port: 443, password: p, client-fingerprint: none }`,
			check: func(c trojanGoClient) bool { return c.SSL.Fingerprint == "" }},
		{node: `{ name: a, type: trojan-go, server: s, port: 443, password: p, alpn: [h2] }`, said: "不发送 ALPN"},
		{node: `{ name: a, type: trojan-go, server: s, port: 443, password: p, network: ws, ws-opts: { path: ws, max-early-data: 2048 } }`, said: "没有 early data",
			check: func(c trojanGoClient) bool { return c.Websocket.Path == "/ws" }},
		{node: `{ name: a, type: trojan-go, server: s, port: 443, password: p, network: grpc }`, err: "没有 grpc 传输"},
		{node: `{ name: a, type: trojan-go, server: s, port: 443, password: p, network: ws, ws-opts: { v2ray-http-upgrade: true } }`, err: "没有 HTTPUpgrade"},
		{node: `{ name: a, type: trojan-go, server: s, port: 443, password: p, mux: { enabled: true, concurrency: 4 } }`,
			check: func(c trojanGoClient) bool { return c.Mux.Enabled && c.Mux.Concurrency == 4 }},
		{node: `{ name: a, type: trojan, server: s, port: 443, password: p, smux: { enabled: true }, ss-opts: { enabled: true, password: x } }`,
			check: func(c trojanGoClient) bool {
				return c.Mux.Enabled && c.Shadowsocks.Enabled && c.Shadowsocks.Method == "AES-128-GCM"
			}},
		{node: `{ name: a, type: trojan-go, server: s, port: 443, password: p, ip-version: ipv4, tfo: true }`, said: "trojan-go 没有 tfo",
			check: func(c trojanGoClient) bool { return c.TCP.PreferIPv4 }},
	} {
		n := model.NewNode(mapping(t, c.node), diag.Pos{})
		b, _, warns, err := TrojanGoConfig(n, Ports{Local: 1}, "", nil)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%s: err %v, want %q", c.node, err, c.err)
			}
			continue
		}
		var cfg trojanGoClient
		json.Unmarshal(b, &cfg)
		if err != nil || !strings.Contains(strings.Join(warns, "\n"), c.said) || c.check != nil && !c.check(cfg) {
			t.Errorf("%s: %v %q\n%s", c.node, err, warns, b)
		}
	}
}

// Trojan with an inner shadowsocks layer goes to trojan-go for kernels
// without one; its udp setting reaches the SOCKS5 node the kernel uses.
func TestTrojanSSInSidecar(t *testing.T) {
	p, err := model.Parse([]byte(`
nodes:
  - { name: ts, type: trojan, server: s, port: 443, password: p, udp: false, ss-opts: { enabled: true, method: aes-128-gcm, password: x } }
routes: { default: ts }
`), "profile.yaml")
	if err != nil {
		t.Fatal(err)
	}
	res := compile.Compile(p)
	if Needs(res.Proxies[0], true) || !Needs(res.Proxies[0], false) {
		t.Fatal("trojan ss-opts: only kernels without it need the sidecar")
	}
	enc, cars, _, _, err := Plan(res, map[string]Ports{"ts": {Local: 20001}}, nil, false)
	if err != nil || len(cars) != 1 {
		t.Fatalf("plan: %v %v", cars, err)
	}
	if udp := model.Lookup(enc.Proxies[0].Node.Raw, "udp"); udp == nil || udp.Value != "false" {
		t.Errorf("the SOCKS5 node relays UDP the node does not: %v", udp)
	}
}
