package compile

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"nautilus/internal/model"
)

const baseNodes = `
nodes:
  - { name: a, type: ss, server: a.example.com, port: 1, cipher: aes-128-gcm, password: x, udp: true }
  - { name: b, type: socks5, server: 192.0.2.2, port: 2 }
  - { name: c, type: vmess, server: c.example.com, port: 3, uuid: u, alterId: 0, cipher: auto }
  - { name: h, type: http, server: 192.0.2.4, port: 4 }
  - { name: q, type: hysteria2, server: 192.0.2.5, port: 5, password: x }
`

func compileSrc(t *testing.T, src string) *Result {
	t.Helper()
	p, err := model.Parse([]byte(baseNodes+src), "profile.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return Compile(p)
}

func mustCompile(t *testing.T, src string) *Result {
	t.Helper()
	res := compileSrc(t, src)
	if err := res.Diags.Err(); err != nil {
		t.Fatal(err)
	}
	return res
}

func wantError(t *testing.T, src, substr string) {
	t.Helper()
	res := compileSrc(t, src)
	err := res.Diags.Err()
	if err == nil || !strings.Contains(err.Error(), substr) {
		t.Errorf("want error containing %q, got %v", substr, err)
	}
}

func proxies(res *Result) []string {
	var out []string
	for _, p := range res.Proxies {
		s := p.Name + "=" + p.Node.Name
		if p.Upstream != "" {
			s += "<" + p.Upstream
		}
		out = append(out, s)
	}
	return out
}

func TestChainExpansion(t *testing.T) {
	res := mustCompile(t, `
groups:
  - { name: G, type: url-test, members: [a, c] }
chains:
  X: [G, b, c]
routes:
  default: X
`)
	want := []string{"a=a", "b=b", "c=c", "h=h", "q=q", "X›1›b=b<G", "X=c<X›1›b"}
	if got := proxies(res); !slices.Equal(got, want) {
		t.Errorf("proxies:\n got  %q\n want %q", got, want)
	}
	if exit := res.Proxies[len(res.Proxies)-1]; exit.Kind != ProxyChainExit || exit.Chain != "X" || exit.Hop != 2 {
		t.Errorf("exit proxy = %+v", exit)
	}
}

func TestInlineChains(t *testing.T) {
	res := mustCompile(t, `
chains:
  Named: [a, b]
routes:
  default: DIRECT
  entries:
    x.com: [a, c]
    y.com: [a, c]
    z.com: [a, b]
`)
	var targets []string
	for _, r := range res.Rules {
		if !r.Origin.Builtin {
			targets = append(targets, r.Value+">"+r.Target)
		}
	}
	want := []string{"x.com>a→c", "y.com>a→c", "z.com>Named", ">DIRECT"}
	if !slices.Equal(targets, want) {
		t.Errorf("targets:\n got  %q\n want %q", targets, want)
	}
	if len(res.Chains) != 2 {
		t.Errorf("want 2 chains (identical inline chains shared, named chain reused), got %d", len(res.Chains))
	}
}

func TestNestedChains(t *testing.T) {
	res := mustCompile(t, `
groups:
  - { name: G, type: select, members: [a, c] }
chains:
  Inner: [a, b]
  Outer: [G, Inner]
  Via: [Inner, c]
routes:
  default: DIRECT
`)
	got := proxies(res)
	for _, want := range []string{
		"Outer›1›a=a<G", "Outer=b<Outer›1›a", // Inner flattened after the first hop
		"Via=c<Inner", // a chain as the first hop is referenced by name
	} {
		if !slices.Contains(got, want) {
			t.Errorf("proxies %q missing %q", got, want)
		}
	}
}

func TestChainErrors(t *testing.T) {
	cases := []struct{ name, src, want string }{
		{"single hop", "chains:\n  X: [a]\n", "至少需要两跳"},
		{"unknown hop", "chains:\n  X: [a, nope]\n", "不存在"},
		{"builtin hop", "chains:\n  X: [DIRECT, a]\n", "不能是 DIRECT"},
		{"group after first", "groups:\n  - { name: G, type: select, members: [a] }\nchains:\n  X: [a, G]\n", "只能放在链的第一跳"},
		{"nested chain starting with group",
			"groups:\n  - { name: G, type: select, members: [a] }\nchains:\n  In: [G, b]\n  X: [c, In]\n", "只能由节点组成"},
		{"self nesting", "chains:\n  X: [a, Y]\n  Y: [b, X]\n", "嵌套引用"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			wantError(t, tt.src+"routes:\n  default: DIRECT\n", tt.want)
		})
	}
}

func TestCycles(t *testing.T) {
	// The loop only exists when the chain is selected inside the group,
	// which mihomo would not notice until a connection recursed.
	wantError(t, `
groups:
  - { name: P, type: select, members: [a, X] }
chains:
  X: [P, b]
routes:
  default: P
`, "循环引用")
}

func TestHandWrittenDialerProxyLoop(t *testing.T) {
	p, err := model.Parse([]byte(`
nodes:
  - { name: a, type: socks5, server: 192.0.2.1, port: 1, dialer-proxy: b }
  - { name: b, type: socks5, server: 192.0.2.2, port: 2, dialer_proxy: a }
routes:
  default: a
`), "profile.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := Compile(p).Diags.Err(); err == nil || !strings.Contains(err.Error(), "循环引用") {
		t.Errorf("want loop error, got %v", err)
	}
}

func TestUDPWarnings(t *testing.T) {
	cases := []struct {
		chain    string
		wantWarn string // empty = no warning
	}{
		{"[h, q]", "h"},   // http cannot relay UDP for the QUIC hop
		{"[a, q]", ""},    // ss with udp: true can
		{"[b, q]", "b"},   // socks5 without udp: true
		{"[G, q]", "h"},   // a group as first hop: every member must relay UDP
		{"[q, b, c]", ""}, // TCP hops after a UDP hop are fine
	}
	for _, tt := range cases {
		res := mustCompile(t, fmt.Sprintf(`
groups:
  - { name: G, type: select, members: [a, h] }
chains:
  X: %s
routes:
  default: DIRECT
`, tt.chain))
		var warns []string
		for _, d := range res.Diags {
			warns = append(warns, d.Msg)
		}
		got := strings.Join(warns, "\n")
		switch {
		case tt.wantWarn == "" && got != "":
			t.Errorf("%s: unexpected warning %q", tt.chain, got)
		case tt.wantWarn != "" && !strings.Contains(got, "但 "+tt.wantWarn+" "):
			t.Errorf("%s: want UDP warning naming %q, got %q", tt.chain, tt.wantWarn, got)
		}
	}
}

func TestSanitizedNames(t *testing.T) {
	p, err := model.Parse([]byte(`
nodes:
  - { name: "HK, 01 ", type: ss, server: 192.0.2.1, port: 1, cipher: aes-128-gcm, password: x }
groups:
  - { name: G, type: select, members: ["HK, 01"] }
routes:
  default: "HK, 01"
`), "profile.yaml")
	if err != nil {
		t.Fatal(err)
	}
	res := Compile(p)
	if err := res.Diags.Err(); err != nil {
		t.Fatal(err)
	}
	if res.Proxies[0].Name != "HK， 01" {
		t.Errorf("name = %q, want comma replaced and spaces trimmed", res.Proxies[0].Name)
	}
	if res.Groups[0].Members[0] != "HK， 01" || res.Rules[len(res.Rules)-1].Target != "HK， 01" {
		t.Errorf("references did not follow the rename: %v / %s", res.Groups[0].Members, res.Rules[len(res.Rules)-1].Target)
	}
	if len(res.Diags) != 1 || !strings.Contains(res.Diags[0].Msg, "已改为") {
		t.Errorf("want one rename warning, got %v", res.Diags)
	}
}

func TestNamespace(t *testing.T) {
	wantError(t, "groups:\n  - { name: a, type: select, members: [b] }\nroutes:\n  default: DIRECT\n", "重复")
	wantError(t, "groups:\n  - { name: GLOBAL, type: select, members: [b] }\nroutes:\n  default: DIRECT\n", "保留名字")
	wantError(t, "routes:\n  default: nowhere\n", "找不到出口")
	wantError(t, "groups:\n  - { name: G, type: weird, members: [a] }\nroutes:\n  default: G\n", "type 应该是")
	wantError(t, "groups:\n  - { name: G, type: select, members: [G] }\nroutes:\n  default: G\n", "不能包含它自己")
	wantError(t, "groups:\n  - { name: G, type: select }\nroutes:\n  default: G\n", "没有任何成员")
}

func TestGroupFilterAndGlobal(t *testing.T) {
	res := mustCompile(t, `
groups:
  - { name: Auto, type: auto, filter: "^[ab]$" }
chains:
  X: [Auto, c]
routes:
  default: Auto
`)
	auto := res.Groups[0]
	if auto.Type != "url-test" || !slices.Equal(auto.Members, []string{"a", "b"}) || auto.URL == "" || auto.Interval == 0 {
		t.Errorf("Auto group = %+v", auto)
	}
	global := res.Groups[len(res.Groups)-1]
	want := []string{"Auto", "X", "a", "b", "c", "h", "q", "DIRECT"}
	if global.Name != GlobalGroup || !slices.Equal(global.Members, want) {
		t.Errorf("GLOBAL = %v, want %v (no chain hops)", global.Members, want)
	}
}

func TestSettings(t *testing.T) {
	res := mustCompile(t, "tun: { enable: true }\nroutes:\n  default: DIRECT\n")
	s := res.Settings
	if !s.DNS.Enable || s.DNS.Mode != "fake-ip" || s.TUN.Stack != "mixed" || s.MixedPort != 7890 || s.Mode != "rule" {
		t.Errorf("settings with TUN = %+v", s)
	}
	wantError(t, "tun: { enable: true }\ndns: { enable: false }\nroutes:\n  default: DIRECT\n", "必须开启 DNS")
	wantError(t, "mode: fast\nroutes:\n  default: DIRECT\n", "mode 应该是")
}
