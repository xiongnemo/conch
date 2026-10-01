package mihomo

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"nautilus/internal/backend"
	"nautilus/internal/compile"
	"nautilus/internal/model"
)

var update = flag.Bool("update", false, "rewrite golden files")

// goldenCases are profiles whose compiled output is checked into testdata.
// The example profile is included so the documentation never goes stale.
func goldenCases(t *testing.T) map[string]string {
	cases := map[string]string{"example": "../../../examples/profile.yaml"}
	files, err := filepath.Glob("testdata/*.profile.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		cases[strings.TrimSuffix(filepath.Base(f), ".profile.yaml")] = f
	}
	return cases
}

func encodeFile(t *testing.T, path string, opts backend.Options) *backend.Artifact {
	t.Helper()
	p, err := model.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	res := compile.Compile(p)
	if err := res.Diags.Err(); err != nil {
		t.Fatal(err)
	}
	art, err := Backend{}.Encode(res, opts)
	if err != nil {
		t.Fatal(err)
	}
	return art
}

func TestGolden(t *testing.T) {
	for name, path := range goldenCases(t) {
		t.Run(name, func(t *testing.T) {
			art := encodeFile(t, path, backend.Options{})
			manifest, err := json.MarshalIndent(art.Manifest, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			checkGolden(t, "testdata/"+name+".golden.yaml", art.Config)
			checkGolden(t, "testdata/"+name+".manifest.golden.json", append(manifest, '\n'))
		})
	}
}

func checkGolden(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update to create it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s is out of date; run go test ./internal/backend/mihomo -update and review the diff.\ngot:\n%s", path, got)
	}
}

// TestGoldenAcceptedByMihomo runs every golden config through `mihomo -t`.
// Set NAUTILUS_MIHOMO to a mihomo binary to enable it, e.g.
// NAUTILUS_MIHOMO=$(nautilus kernel path).
func TestGoldenAcceptedByMihomo(t *testing.T) {
	bin := os.Getenv("NAUTILUS_MIHOMO")
	if bin == "" {
		t.Skip("NAUTILUS_MIHOMO not set")
	}
	for name := range goldenCases(t) {
		t.Run(name, func(t *testing.T) {
			out, err := exec.Command(bin, "-t", "-d", t.TempDir(), "-f", "testdata/"+name+".golden.yaml").CombinedOutput()
			if err != nil || !strings.Contains(string(out), "test is successful") {
				t.Errorf("mihomo rejected %s: %v\n%s", name, err, out)
			}
		})
	}
}

func TestControllerOptions(t *testing.T) {
	art := encodeFile(t, "testdata/tun.profile.yaml", backend.Options{
		ControllerUnix: "/run/nautilus/mihomo.sock",
		Controller:     "127.0.0.1:9090",
	})
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
