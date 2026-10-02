package sidecar

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xiongnemo/conch/internal/backend"
	"github.com/xiongnemo/conch/internal/backend/mihomo"
	"github.com/xiongnemo/conch/internal/backend/xray"
	"github.com/xiongnemo/conch/internal/compile"
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
	enc, cars, fwd, err := Plan(res, map[string]Ports{"tg": {Local: 20001}, "经中转": {Local: 20002, Forward: 20003}})
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
	if _, _, _, err := Plan(enc, nil); err != nil {
		t.Errorf("planning a planned result again: %v", err)
	}
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
