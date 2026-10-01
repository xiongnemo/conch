package xray

import (
	"encoding/json"
	"math/rand/v2"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"nautilus/internal/backend"
	"nautilus/internal/backend/backendtest"
	"nautilus/internal/lists"
)

func TestGolden(t *testing.T) {
	backendtest.Golden(t, Backend{}, ".json")
}

// TestGoldenAcceptedByXray runs every golden config through `xray run -test`.
// It needs an xray binary and the geodata its rules reference:
//
//	NAUTILUS_XRAY=$(nautilus kernel path xray) NAUTILUS_XRAY_ASSETS=<dir with geoip.dat, geosite.dat>
func TestGoldenAcceptedByXray(t *testing.T) {
	bin, assets := os.Getenv("NAUTILUS_XRAY"), os.Getenv("NAUTILUS_XRAY_ASSETS")
	if bin == "" || assets == "" {
		t.Skip("NAUTILUS_XRAY or NAUTILUS_XRAY_ASSETS not set")
	}
	for _, f := range backendtest.Configs(t, ".json") {
		t.Run(f, func(t *testing.T) {
			cmd := exec.Command(bin, "run", "-test", "-c", f)
			cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+assets)
			out, err := cmd.CombinedOutput()
			if err != nil || !strings.Contains(string(out), "Configuration OK") {
				t.Errorf("xray rejected %s: %v\n%s", f, err, out)
			}
		})
	}
}

// Tags must be prefix-free: xray selects balancer members by tag prefix.
func TestTagsArePrefixFree(t *testing.T) {
	words := []string{"香港", "香港 01", "香港 012", "A", "A›1›x", "A›2›y", "AB", "REJECT", "REJECT-DROP", "x"}
	rng := rand.New(rand.NewPCG(3, 4))
	for range 200 {
		var names []string
		for range 1 + rng.IntN(8) {
			names = append(names, words[rng.IntN(len(words))])
		}
		tags := assignTags(names)
		for _, a := range names {
			for _, b := range names {
				if a != b && strings.HasPrefix(tags[b], tags[a]) {
					t.Fatalf("names %q: tag %q is a prefix of %q", names, tags[a], tags[b])
				}
			}
		}
	}
	tags := assignTags([]string{"香港 01", "香港 02"})
	if tags["香港 01"] != "香港 01" {
		t.Errorf("names without prefix relations must keep their tags, got %q", tags["香港 01"])
	}
}

func TestEntryRules(t *testing.T) {
	data, _ := os.ReadFile("../testdata/lists/streaming.yaml")
	entries, skipped, err := lists.Parse(data, "yaml", "classical")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(skipped, []string{"USER-AGENT,Netflix*"}) {
		t.Errorf("skipped = %q", skipped)
	}
	got, _ := json.Marshal(entryRules(entries))
	want := `[{"domain":["domain:netflix.com","full:api.example-stream.com","keyword:nflx"]},{"ip":["23.246.0.0/18"]},{"process":["Netflix"]}]`
	if string(got) != want {
		t.Errorf("entryRules:\n got  %s\n want %s", got, want)
	}
}

func TestAPIOptions(t *testing.T) {
	art, d := backendtest.Build(t, Backend{}, "../testdata/groups.profile.yaml", backend.Options{ControllerUnix: "/run/nautilus/xray.sock"})
	if art == nil {
		t.Fatal(d.Err())
	}
	var cfg config
	if err := json.Unmarshal(art.Config, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.API == nil || cfg.API.Listen != "" || cfg.Stats == nil || cfg.Policy == nil ||
		!slices.Contains(cfg.API.Services, "ObservatoryService") {
		t.Errorf("api = %+v, stats = %v, policy = %v", cfg.API, cfg.Stats, cfg.Policy)
	}
	in := cfg.Inbounds[len(cfg.Inbounds)-1]
	if in.Protocol != "dokodemo-door" || in.Listen != "/run/nautilus/xray.sock" ||
		cfg.Routing.Rules[0].InboundTag[0] != apiTag || cfg.Routing.Rules[0].OutboundTag != apiTag {
		t.Errorf("unix API inbound = %+v, first rule = %+v", in, cfg.Routing.Rules[0])
	}
	if _, d := backendtest.Build(t, Backend{}, "../testdata/groups.profile.yaml", backend.Options{ControllerPipe: `\\.\pipe\x`}); !d.HasErrors() {
		t.Error("named pipes are not supported by xray and must be rejected")
	}
}

// Manifest indexes must point at the emitted rule even when internal
// rules (API, group dispatch) come first.
func TestManifestIndexes(t *testing.T) {
	for _, opts := range []backend.Options{{}, {ControllerUnix: "/run/x.sock"}} {
		art, d := backendtest.Build(t, Backend{}, "../testdata/groups.profile.yaml", opts)
		if art == nil {
			t.Fatal(d.Err())
		}
		var cfg config
		json.Unmarshal(art.Config, &cfg)
		for _, mr := range art.Manifest.Rules {
			got, _ := json.Marshal(cfg.Routing.Rules[mr.Index])
			if string(got) != mr.Rule {
				t.Errorf("opts %+v: manifest rule %d is %s, config has %s", opts, mr.Index, mr.Rule, got)
			}
		}
	}
}
