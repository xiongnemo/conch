package mihomo

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"nautilus/internal/backend"
	"nautilus/internal/backend/backendtest"
)

func TestGolden(t *testing.T) {
	backendtest.Golden(t, Backend{}, ".yaml")
}

// TestGoldenAcceptedByMihomo runs every golden config through `mihomo -t`.
// Set NAUTILUS_MIHOMO to a mihomo binary to enable it, e.g.
// NAUTILUS_MIHOMO=$(nautilus kernel path mihomo).
func TestGoldenAcceptedByMihomo(t *testing.T) {
	bin := os.Getenv("NAUTILUS_MIHOMO")
	if bin == "" {
		t.Skip("NAUTILUS_MIHOMO not set")
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

func TestControllerOptions(t *testing.T) {
	art, d := backendtest.Build(t, Backend{}, "../testdata/tun.profile.yaml", backend.Options{
		ControllerUnix: "/run/nautilus/mihomo.sock",
		Controller:     "127.0.0.1:9090",
	})
	if art == nil {
		t.Fatal(d.Err())
	}
	cfg := string(art.Config)
	for _, want := range []string{
		"external-controller-unix: /run/nautilus/mihomo.sock",
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
