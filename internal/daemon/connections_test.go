package daemon

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"nautilus/internal/backend"
	"nautilus/internal/compile"
	"nautilus/internal/control"
	"nautilus/internal/route"
)

func TestFailures(t *testing.T) {
	var f failures
	now := time.Now()
	dial := control.DialFailure{Source: "127.0.0.1:46178", Via: "dead", Host: "www.example.com", Port: "80", Error: "connect: connection refused"}
	for range 5 { // the kernel retries one connection several times
		f.add(dial, now)
	}
	dial.Source, dial.Error = "127.0.0.1:46200", "timeout"
	f.add(dial, now.Add(time.Second))
	f.add(control.DialFailure{Source: "127.0.0.1:46812", Via: "AI-Exit", Host: "chat.openai.com", Port: "80", Error: "refused"}, now.Add(2*time.Second))
	got := f.list()
	if len(got) != 2 || got[0].Host != "chat.openai.com" || got[0].Via != "AI-Exit" || got[0].Error != "refused" {
		t.Fatalf("failures = %+v", got)
	}
	if w := got[1]; w.Host != "www.example.com" || w.Count != 2 || w.Via != "dead" || w.Error != "timeout" {
		t.Errorf("www.example.com = %+v", w)
	}
	f.clear()
	if len(f.list()) != 0 {
		t.Error("clear did not forget failures")
	}
}

// The log follows the profile's log-level even when the kernel runs
// more verbosely for nautilus's sake.
func TestShown(t *testing.T) {
	for _, c := range []struct {
		level, setting string
		want           bool
	}{
		{"debug", "info", false}, {"info", "info", true}, {"warning", "info", true},
		{"info", "warning", false}, {"error", "warning", true}, {"", "error", true}, {"debug", "", true},
	} {
		if got := shown(c.level, c.setting); got != c.want {
			t.Errorf("shown(%q, %q) = %v", c.level, c.setting, got)
		}
	}
}

func TestSuggest(t *testing.T) {
	for host, want := range map[string][]string{
		"api.openai.com":   {"openai.com", "api.openai.com"},
		"openai.com":       {"openai.com"},
		"www.bbc.co.uk":    {"bbc.co.uk", "www.bbc.co.uk"},
		"Chat.OpenAI.com.": {"openai.com", "chat.openai.com"},
	} {
		if got := Suggest(host); !slices.Equal(got, want) {
			t.Errorf("Suggest(%q) = %q, want %q", host, got, want)
		}
	}
}

type fakeConns struct {
	control.Kernel
	conns []control.Connection
}

func (f fakeConns) Connections(context.Context) ([]control.Connection, error) { return f.conns, nil }

// xray gets one rule for a subscription's run of rules; a connection still
// names the rule that matched, or the run when its host does not tell.
func TestConnectionsInMergedRules(t *testing.T) {
	sub := route.Origin{Key: "机场", Imported: true}
	res := &compile.Result{Settings: compile.Settings{Mode: "rule"}, Rules: []route.Rule{
		{Match: route.MatchDomainSuffix, Value: "a.example", Target: "代理", Origin: sub},
		{Match: route.MatchDomainSuffix, Value: "b.example", Target: "代理", Origin: sub},
		{Match: route.MatchFinal, Target: "代理", Origin: route.Origin{Tier: route.TierDefault, Key: "default"}},
	}}
	art := &backend.Artifact{Manifest: &backend.Manifest{Rules: []backend.ManifestRule{{Index: 0, Last: 1, Tag: "#0-1 机场"}}}}
	d := &Daemon{ctl: fakeConns{conns: []control.Connection{
		{ID: "1", Host: "www.b.example", RuleTag: "#0-1 机场", Chains: []string{"B1"}},
		{ID: "2", Host: "203.0.113.9", RuleTag: "#0-1 机场", Chains: []string{"B1"}},
		{ID: "3", Host: "gone.example", RuleTag: "#7 gone.example", Chains: []string{"B2"}}, // from the config before
	}}, res: res, art: art}
	conns, err := d.Connections(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range conns {
		got[c.ID] = c.Matched + " → " + strings.Join(c.Via, " → ")
	}
	want := map[string]string{"1": "订阅 机场 的规则 域名后缀 b.example → 代理 → B1", "2": "订阅 机场 的 2 条规则之一 → 代理 → B1", "3": "gone.example → B2"}
	if got["1"] != want["1"] || got["2"] != want["2"] || got["3"] != want["3"] {
		t.Errorf("connections = %q, want %q", got, want)
	}
}

// A subscription repeating one of the user's entries does not take the
// credit for connections the entry routed: the first rule matches.
func TestConnectionsFirstRuleWins(t *testing.T) {
	res := &compile.Result{Settings: compile.Settings{Mode: "rule"}, Rules: []route.Rule{
		{Match: route.MatchDomainSuffix, Value: "google.com", Target: "A", Origin: route.Origin{Tier: route.TierDomain, Key: "google.com"}},
		{Match: route.MatchDomainSuffix, Value: "google.com", Target: "B", Origin: route.Origin{Key: "机场", Imported: true}},
	}}
	art := &backend.Artifact{Manifest: &backend.Manifest{Rules: []backend.ManifestRule{
		{Index: 0, Rule: "DOMAIN-SUFFIX,google.com,A"}, {Index: 1, Rule: "DOMAIN-SUFFIX,google.com,B"},
	}}}
	d := &Daemon{ctl: fakeConns{conns: []control.Connection{{ID: "1", Host: "www.google.com", Rule: "DomainSuffix", RulePayload: "google.com", Chains: []string{"A"}}}}, res: res, art: art}
	conns, err := d.Connections(context.Background())
	if err != nil || len(conns) != 1 || conns[0].Matched != "手动条目 google.com" {
		t.Errorf("connections = %+v, %v", conns, err)
	}
}
