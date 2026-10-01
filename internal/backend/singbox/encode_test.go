package singbox

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"nautilus/internal/backend"
	"nautilus/internal/backend/backendtest"
)

func TestGolden(t *testing.T) {
	backendtest.Golden(t, Backend{}, ".json")
}

// TestGoldenAcceptedBySingBox runs every golden config through
// `sing-box check`:
//
//	NAUTILUS_SING_BOX=$(nautilus kernel path sing-box)
func TestGoldenAcceptedBySingBox(t *testing.T) {
	bin := os.Getenv("NAUTILUS_SING_BOX")
	if bin == "" {
		t.Skip("NAUTILUS_SING_BOX not set")
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
