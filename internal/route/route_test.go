package route

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/xiongnemo/conch/internal/diag"
	"github.com/xiongnemo/conch/internal/model"
)

func TestParseTarget(t *testing.T) {
	tests := []struct {
		in       string
		kind     Kind
		value    string
		wantNote bool
	}{
		{"openai.com", KindDomainSuffix, "openai.com", false},
		{"*.google.com", KindDomainSuffix, "google.com", false},
		{".google.com", KindDomainSuffix, "google.com", false},
		{"MAIL.Google.COM.", KindDomainSuffix, "mail.google.com", false},
		{"例子.中国", KindDomainSuffix, "xn--fsqu00a.xn--fiqs8s", false},
		{"=api.example.com", KindDomain, "api.example.com", false},
		{"~Google", KindKeyword, "google", false},
		{"10.0.0.0/8", KindIP, "10.0.0.0/8", false},
		{"10.1.2.3/8", KindIP, "10.0.0.0/8", true},
		{"1.1.1.1", KindIP, "1.1.1.1/32", false},
		{"2001:db8::1", KindIP, "2001:db8::1/128", false},
		{"::ffff:1.2.3.4", KindIP, "1.2.3.4/32", false},
		{"app:Telegram", KindApp, "Telegram", false},
		{"APP:/usr/bin/curl", KindAppPath, "/usr/bin/curl", false},
	}
	for _, tt := range tests {
		got, note, err := ParseTarget(tt.in)
		if err != nil {
			t.Errorf("ParseTarget(%q): %v", tt.in, err)
			continue
		}
		if got.Kind != tt.kind || got.Value != tt.value || (note != "") != tt.wantNote {
			t.Errorf("ParseTarget(%q) = %v %q note=%q, want %v %q note=%v", tt.in, got.Kind, got.Value, note, tt.kind, tt.value, tt.wantNote)
		}
	}
	for _, bad := range []string{"", "a,b", "app:", "~", "exa mple.com", "http://x.com", "fe80::1%eth0", "=", "*."} {
		if _, _, err := ParseTarget(bad); err == nil {
			t.Errorf("ParseTarget(%q) succeeded, want error", bad)
		}
	}
}

// build parses a profile snippet and compiles its routes with a resolver
// that knows the given outbound names.
func build(t *testing.T, src string, known ...string) (*Table, diag.List) {
	t.Helper()
	p, err := model.Parse([]byte(src), "profile.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var d diag.List
	names := append([]string{"DIRECT", "REJECT"}, known...)
	resolve := func(v model.Via, pos diag.Pos) (string, bool) {
		if v.Chain != nil {
			return strings.Join(v.Chain, "→"), true
		}
		if !slices.Contains(names, v.Name) {
			d.Errorf(pos, "未知出口 %q", v.Name)
			return "", false
		}
		return v.Name, true
	}
	return Build(&p.Routes, resolve, &d), d
}

func ruleString(r Rule) string {
	kind := [...]string{"path", "app", "exact", "suffix", "keyword", "ip", "list", "port", "network", "raw", "default"}[r.Match]
	s := fmt.Sprintf("%s:%s→%s", kind, r.Value, r.Target)
	if r.NoResolve {
		s += "(no-resolve)"
	}
	return s
}

// userRules drops the built-in lan rules to keep expectations short.
func userRules(tab *Table) []string {
	var out []string
	for _, r := range tab.Rules {
		if !r.Origin.Builtin {
			out = append(out, ruleString(r))
		}
	}
	return out
}

func TestSpecificityOrder(t *testing.T) {
	tab, d := build(t, `
routes:
  default: Proxy
  entries:
    10.0.0.0/8: A
    google.com: A
    ~goog: A
    app:Telegram: A
    mail.google.com: B
    =api.google.com: B
    10.1.2.3: B
    ~google: B
    10.1.0.0/16: { via: B, resolve: true }
    app:/usr/bin/curl: B
    2001:db8::/32: A
`, "A", "B", "Proxy")
	if len(d) != 0 {
		t.Fatalf("unexpected diagnostics: %v", d)
	}
	want := []string{
		"path:/usr/bin/curl→B",
		"app:Telegram→A",
		"exact:api.google.com→B",
		"suffix:mail.google.com→B",
		"suffix:google.com→A",
		"keyword:google→B",
		"keyword:goog→A",
		"ip:10.1.2.3/32→B(no-resolve)",
		"ip:2001:db8::/32→A(no-resolve)",
		"ip:10.1.0.0/16→B",
		"ip:10.0.0.0/8→A(no-resolve)",
		"default:→Proxy",
	}
	if got := userRules(tab); !slices.Equal(got, want) {
		t.Errorf("rules:\n got  %q\n want %q", got, want)
	}
}

// Shuffling manual entries must never change the compiled table.
func TestEntryOrderDoesNotMatter(t *testing.T) {
	lines := []string{
		"    openai.com: A", "    chat.openai.com: B", "    =openai.com: C", "    ~openai: A",
		"    8.8.8.8: B", "    8.8.0.0/16: A", "    192.168.1.0/24: B", "    app:curl: C",
		"    fd00::/8: A", "    claude.ai: [A, B]", "    lan: { via: DIRECT, resolve: true }",
	}
	var want []string
	rng := rand.New(rand.NewPCG(1, 2))
	for i := range 50 {
		shuffled := slices.Clone(lines)
		rng.Shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })
		tab, d := build(t, "routes:\n  default: A\n  entries:\n"+strings.Join(shuffled, "\n")+"\n", "A", "B", "C")
		if len(d) != 0 {
			t.Fatalf("unexpected diagnostics: %v", d)
		}
		var got []string
		for _, r := range tab.Rules {
			got = append(got, ruleString(r))
		}
		if i == 0 {
			want = got
		} else if !slices.Equal(got, want) {
			t.Fatalf("shuffle %d changed the table:\n got  %q\n want %q", i, got, want)
		}
	}
}

func TestLANEntry(t *testing.T) {
	t.Run("implicit lan goes direct", func(t *testing.T) {
		tab, _ := build(t, "routes:\n  default: DIRECT\n")
		var lan []string
		for _, r := range tab.Rules {
			if r.Origin.Builtin {
				lan = append(lan, ruleString(r))
			}
		}
		for _, want := range []string{"suffix:localhost→DIRECT", "ip:192.168.0.0/16→DIRECT(no-resolve)", "ip:fe80::/10→DIRECT(no-resolve)"} {
			if !slices.Contains(lan, want) {
				t.Errorf("built-in lan rules %q missing %q", lan, want)
			}
		}
	})
	t.Run("lan off", func(t *testing.T) {
		tab, _ := build(t, "routes:\n  default: DIRECT\n  entries:\n    lan: off\n")
		if len(tab.Rules) != 1 {
			t.Errorf("want only the default rule, got %q", userRules(tab))
		}
	})
	t.Run("explicit entry overrides lan", func(t *testing.T) {
		tab, d := build(t, "routes:\n  default: DIRECT\n  entries:\n    10.0.0.0/8: VPN\n", "VPN")
		if len(d) != 0 {
			t.Fatalf("unexpected diagnostics: %v", d)
		}
		n := 0
		for _, r := range tab.Rules {
			if r.Value == "10.0.0.0/8" {
				n++
				if r.Target != "VPN" || r.Origin.Builtin {
					t.Errorf("10.0.0.0/8 should go to VPN, got %s", ruleString(r))
				}
			}
		}
		if n != 1 {
			t.Errorf("10.0.0.0/8 appears %d times, want 1", n)
		}
	})
}

func TestDuplicateTargets(t *testing.T) {
	_, d := build(t, "routes:\n  default: A\n  entries:\n    google.com: A\n    \"*.Google.com\": A\n", "A")
	if !d.HasErrors() || !strings.Contains(d.Err().Error(), "同一个目标") {
		t.Errorf("want duplicate-target error, got %v", d)
	}
}

func TestLists(t *testing.T) {
	tab, d := build(t, `
routes:
  default: Proxy
  list-mirror: jsdelivr
  lists:
    - { list: ads, via: REJECT }
    - { list: geosite:CN, via: DIRECT }
    - { list: geoip:cn, via: DIRECT }
    - { list: https://example.com/rules/My-List.yaml, via: Proxy }
    - { list: https://example.com/a/ip.mrs, behavior: ipcidr, via: Proxy }
    - { list: ads, via: Proxy }
    - { clash: ["AND,((NETWORK,UDP),(DST-PORT,443)),REJECT", "DOMAIN-REGEX,^a.+,b$,Proxy"] }
`, "Proxy")
	if len(d) != 0 {
		t.Fatalf("unexpected diagnostics: %v", d)
	}
	got := userRules(tab)
	want := []string{
		"list:geosite-category-ads-all→REJECT",
		"list:geosite-cn→DIRECT",
		"list:geoip-cn→DIRECT",
		"list:list-my-list→Proxy",
		"list:list-ip→Proxy",
		"list:geosite-category-ads-all→Proxy",
		"raw:AND,((NETWORK,UDP),(DST-PORT,443)),REJECT→REJECT",
		"raw:DOMAIN-REGEX,^a.+,b$,Proxy→Proxy",
		"default:→Proxy",
	}
	if !slices.Equal(got, want) {
		t.Errorf("rules:\n got  %q\n want %q", got, want)
	}
	if len(tab.Providers) != 5 {
		t.Fatalf("want 5 providers (ads reused), got %d", len(tab.Providers))
	}
	cn := tab.Providers[1]
	if cn.URL != "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/cn.mrs" || cn.Behavior != "domain" || cn.Format != "mrs" {
		t.Errorf("geosite:cn provider = %+v", cn)
	}
	if p := tab.Providers[3]; p.Format != "yaml" || p.Behavior != "classical" {
		t.Errorf("yaml URL provider = %+v", p)
	}
	if raw := tab.Rules[len(tab.Rules)-2]; raw.TargetField != 3 {
		t.Errorf("regex rule target field = %d, want 3", raw.TargetField)
	}
}

func TestListErrors(t *testing.T) {
	for _, tt := range []struct{ list, want string }{
		{"{ list: nope, via: DIRECT }", "不认识的规则列表"},
		{"{ list: gfwlist }", "需要用 via"},
		{"{ list: https://x.com/a.mrs, via: DIRECT }", "behavior"},
		{"{ list: geosite:cn, format: text, via: DIRECT }", "固定"},
		{`{ clash: ["MATCH,DIRECT"] }`, "MATCH"},
		{"{ list: gfwlist, via: Nowhere }", "未知出口"},
	} {
		_, d := build(t, "routes:\n  default: DIRECT\n  lists:\n    - "+tt.list+"\n")
		if !d.HasErrors() || !strings.Contains(d.Err().Error(), tt.want) {
			t.Errorf("%s: want error containing %q, got %v", tt.list, tt.want, d)
		}
	}
}

func TestMissingDefault(t *testing.T) {
	_, d := build(t, "routes:\n  entries:\n    a.com: DIRECT\n")
	if !d.HasErrors() || !strings.Contains(d.Err().Error(), "routes.default") {
		t.Errorf("want missing-default error, got %v", d)
	}
}
