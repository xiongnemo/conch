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

// xray cannot find processes on macOS, so there app entries are an error
// that says so.
func TestNoAppEntriesOnMacOS(t *testing.T) {
	backend.TargetOS = "darwin"
	t.Cleanup(func() { backend.TargetOS = "linux" })
	art, d := backendtest.Build(t, Backend{}, "../../../examples/profile.yaml", backend.Options{Lists: backendtest.Lists})
	if art != nil || !strings.Contains(d.Err().Error(), "xray 后端在 macOS 上不支持按应用分流（app:Telegram）") {
		t.Errorf("diagnostics: %v", d)
	}
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

// Every emitted user rule carries a tag naming the compiled rule it came
// from: xray logs it for each connection, and nautilus maps it back.
func TestRuleTags(t *testing.T) {
	for _, opts := range []backend.Options{{}, {ControllerUnix: "/run/x.sock", Probes: []string{"/run/p1.sock"}}} {
		art, d := backendtest.Build(t, Backend{}, "../testdata/groups.profile.yaml", opts)
		if art == nil {
			t.Fatal(d.Err())
		}
		var cfg config
		json.Unmarshal(art.Config, &cfg)
		emitted := map[string]string{}
		for _, r := range cfg.Routing.Rules {
			if r.RuleTag == "" {
				continue
			}
			if _, dup := emitted[r.RuleTag]; dup {
				t.Errorf("rule tag %q used twice", r.RuleTag)
			}
			data, _ := json.Marshal(r)
			emitted[r.RuleTag] = string(data)
		}
		if len(art.Manifest.Rules) == 0 {
			t.Fatal("no manifest rules")
		}
		for _, mr := range art.Manifest.Rules {
			if emitted[mr.Tag] != mr.Rule {
				t.Errorf("manifest rule %s: config has %s", mr.Rule, emitted[mr.Tag])
			}
			if i, ok := RuleIndex(mr.Tag); !ok || i != mr.Index {
				t.Errorf("RuleIndex(%q) = %d, %v; want %d", mr.Tag, i, ok, mr.Index)
			}
		}
	}
	if _, ok := RuleIndex(ProbeTag(0)); ok {
		t.Error("probe tags must not look like compiled rules")
	}
}

func TestProbes(t *testing.T) {
	opts := backend.Options{ControllerUnix: "/run/n/xray.sock", Probes: []string{"/run/n/p1.sock", "/run/n/p2.sock"}, MinLogLevel: "info"}
	art, d := backendtest.Build(t, Backend{}, "../testdata/groups.profile.yaml", opts)
	if art == nil {
		t.Fatal(d.Err())
	}
	var cfg config
	json.Unmarshal(art.Config, &cfg)
	for i, socket := range opts.Probes {
		tag := ProbeTag(i)
		in := slices.IndexFunc(cfg.Inbounds, func(in inbound) bool { return in.Tag == tag })
		if in < 0 || cfg.Inbounds[in].Listen != socket || cfg.Inbounds[in].Protocol != "http" {
			t.Errorf("probe %d inbound missing: %+v", i, cfg.Inbounds)
		}
		// Probe rules come before every user rule, or a user rule for the
		// test URL's domain would decide where the test goes.
		r := cfg.Routing.Rules[1+i]
		if r.InboundTag[0] != tag || r.BalancerTag != tag {
			t.Errorf("rule %d = %+v, want the probe's", 1+i, r)
		}
		if !slices.ContainsFunc(cfg.Routing.Balancers, func(b balancer) bool { return b.Tag == tag }) {
			t.Errorf("probe %d has no balancer", i)
		}
	}
	if cfg.Log.LogLevel != "info" {
		t.Errorf("log level = %q, want info", cfg.Log.LogLevel)
	}
}
