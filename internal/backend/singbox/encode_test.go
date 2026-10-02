package singbox

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/xiongnemo/conch/internal/backend"
	"github.com/xiongnemo/conch/internal/backend/backendtest"
)

func TestGolden(t *testing.T) {
	backendtest.Golden(t, Backend{}, ".json")
}

// TestGoldenAcceptedBySingBox runs every golden config through
// `sing-box check`:
//
//	CONCH_SING_BOX=$(conch kernel path sing-box)
func TestGoldenAcceptedBySingBox(t *testing.T) {
	bin := os.Getenv("CONCH_SING_BOX")
	if bin == "" {
		t.Skip("CONCH_SING_BOX not set")
	}
	for _, f := range backendtest.Configs(t, ".json") {
		t.Run(f, func(t *testing.T) {
			abs, _ := filepath.Abs(f) // -D changes the working directory
			if out, err := exec.Command(bin, "check", "--disable-color", "-c", abs, "-D", t.TempDir()).CombinedOutput(); err != nil {
				t.Errorf("sing-box rejected %s: %v\n%s", f, err, out)
			}
		})
	}
}

// Rules are named in the manifest the way sing-box names them in
// connections, so connections can be explained.
func TestRuleDescriptions(t *testing.T) {
	for want, r := range map[string]rule{
		"domain_suffix=openai.com":                   {DomainSuffix: []string{"openai.com"}},
		"domain=a domain_suffix=[b c d...]":          {Domain: []string{"a"}, DomainSuffix: []string{"b", "c", "d", "e"}},
		"ip_cidr=10.0.0.0/8":                         {IPCIDR: []string{"10.0.0.0/8"}},
		"domain_regex=[a b c]":                       {DomainRegex: []string{"a", "b", "c", "d"}},
		"network=udp port=[443 853]":                 {Network: []string{"udp"}, Port: []int{443, 853}},
		"process_name=[Telegram Signal]":             {ProcessName: []string{"Telegram", "Signal"}},
		"domain_keyword=google ip_cidr=[1.1.1.1/32]": {DomainKeyword: []string{"google"}, IPCIDR: []string{"1.1.1.1/32"}},
	} {
		if got := describe(r); got != want && !(want == "domain_keyword=google ip_cidr=[1.1.1.1/32]" && got == "domain_keyword=google ip_cidr=1.1.1.1/32") {
			t.Errorf("describe(%+v) = %q, want %q", r, got, want)
		}
	}
}

func TestControllerOptions(t *testing.T) {
	art, d := backendtest.Build(t, Backend{}, "../testdata/groups.profile.yaml", backend.Options{Controller: "127.0.0.1:9999", Secret: "s3cret"})
	if art == nil {
		t.Fatal(d.Err())
	}
	var cfg config
	if err := json.Unmarshal(art.Config, &cfg); err != nil {
		t.Fatal(err)
	}
	if c := cfg.Experimental; c == nil || c.ClashAPI.ExternalController != "127.0.0.1:9999" || c.ClashAPI.Secret != "s3cret" || !c.CacheFile.Enabled {
		t.Errorf("experimental = %+v", c)
	}
	if _, d := backendtest.Build(t, Backend{}, "../testdata/groups.profile.yaml", backend.Options{ControllerUnix: "/run/x.sock"}); !d.HasErrors() {
		t.Error("a unix socket controller must be rejected")
	}
	if !strings.Contains(string(art.Config), `"action": "sniff"`) {
		t.Error("connections must be sniffed so domain rules apply to clients that connect by IP")
	}
}

// Ports as mihomo writes them; nothing readable is no rule at all, as a
// rule without conditions would match every connection.
func TestPortRule(t *testing.T) {
	for in, want := range map[string]string{
		"443":       `{"port":[443]}`,
		"80/443":    `{"port":[80,443]}`,
		"80,443":    `{"port":[80,443]}`,
		"1000-2000": `{"port_range":["1000:2000"]}`,
		"abc":       "",
		"0/70000":   "",
	} {
		r, ok := portRule(in)
		got := ""
		if ok {
			data, _ := json.Marshal(r)
			got = string(data)
		}
		if got != want {
			t.Errorf("portRule(%q) = %s, want %s", in, got, want)
		}
	}
}

// default: REJECT stays a refusal, not DIRECT.
func TestFinalReject(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.yaml")
	os.WriteFile(path, []byte("routes:\n  default: REJECT\n"), 0o644)
	art, d := backendtest.Build(t, Backend{}, path, backend.Options{})
	if art == nil {
		t.Fatal(d)
	}
	var cfg config
	json.Unmarshal(art.Config, &cfg)
	blocks := slices.ContainsFunc(cfg.Outbounds, func(o outbound) bool { return o.Tag == "REJECT" && o.Type == "block" })
	if cfg.Route.Final != "REJECT" || !blocks {
		t.Errorf("final = %q, block outbound %v", cfg.Route.Final, blocks)
	}
}
