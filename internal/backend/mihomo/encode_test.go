package mihomo

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/xiongnemo/conch/internal/backend"
	"github.com/xiongnemo/conch/internal/backend/backendtest"
)

func TestGolden(t *testing.T) {
	backendtest.Golden(t, Backend{}, ".yaml")
}

// TestGoldenAcceptedByMihomo runs every golden config through `mihomo -t`.
// Set CONCH_MIHOMO to a mihomo binary to enable it, e.g.
// CONCH_MIHOMO=$(conch kernel path mihomo).
func TestGoldenAcceptedByMihomo(t *testing.T) {
	bin := os.Getenv("CONCH_MIHOMO")
	if bin == "" {
		t.Skip("CONCH_MIHOMO not set")
	}
	for _, f := range backendtest.Configs(t, ".yaml") {
		t.Run(f, func(t *testing.T) {
			out, err := exec.Command(bin, "-t", "-d", t.TempDir(), "-f", f).CombinedOutput()
			if err != nil || !strings.Contains(string(out), "test is successful") {
				t.Errorf("mihomo rejected %s: %v\n%s", f, err, out)
			}
		})
	}
}

// mihomo dials vless and trojan "over mKCP" with plain TCP; only vmess has it.
func TestMKCPOnlyVMess(t *testing.T) {
	for node, ok := range map[string]bool{
		`{ name: k, type: vmess, server: 192.0.2.1, port: 4000, uuid: 11111111-2222-3333-4444-555555555555, alterId: 0, cipher: auto, network: mkcp }`: true,
		`{ name: k, type: vless, server: 192.0.2.1, port: 4000, uuid: 11111111-2222-3333-4444-555555555555, network: kcp }`:                            false,
		`{ name: k, type: trojan, server: 192.0.2.1, port: 4000, password: p, network: mkcp }`:                                                         false,
	} {
		art, said := backendtest.BuildNode(t, Backend{}, node)
		if (art != nil) != ok || !ok && !strings.Contains(said, "mihomo 只有 vmess 能走 mKCP") {
			t.Errorf("%s: config made: %v\n%s", node, art != nil, said)
		}
	}
}

func TestControllerOptions(t *testing.T) {
	art, d := backendtest.Build(t, Backend{}, "../testdata/tun.profile.yaml", backend.Options{
		ControllerUnix: "/run/conch/mihomo.sock",
		Controller:     "127.0.0.1:9090",
	})
	if art == nil {
		t.Fatal(d.Err())
	}
	cfg := string(art.Config)
	for _, want := range []string{
		"external-controller-unix: /run/conch/mihomo.sock",
		"external-controller: 127.0.0.1:9090",
		// An empty allow-origins list would allow every origin.
		"allow-origins:\n    - " + corsNobody,
		"allow-private-network: false",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %q:\n%s", want, cfg)
		}
	}
	if strings.Contains(cfg, "secret") {
		t.Error("the secret must be passed via the environment, not written to the config")
	}
}
