package explain

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/xiongnemo/conch/internal/compile"
	"github.com/xiongnemo/conch/internal/lists"
	"github.com/xiongnemo/conch/internal/model"
	"github.com/xiongnemo/conch/internal/route"
)

const profile = `
nodes:
  - { name: A, type: socks5, server: 192.0.2.1, port: 1 }
  - { name: B, type: socks5, server: 192.0.2.2, port: 2 }
groups:
  - { name: G, type: select, members: [A, B] }
routes:
  default: G
  entries:
    google.com: A
    mail.google.com: DIRECT
    app:Telegram: B
    149.154.160.0/20: { via: B, resolve: true }
  lists:
    - { list: geosite:cn, via: DIRECT }
    - { list: geoip:cn, via: DIRECT }
`

func explainer(t *testing.T, src string, kernel string) *Explainer {
	t.Helper()
	p, err := model.Parse([]byte(src), "profile.yaml")
	if err != nil {
		t.Fatal(err)
	}
	res := compile.Compile(p)
	if err := res.Diags.Err(); err != nil {
		t.Fatal(err)
	}
	return &Explainer{
		Result: res,
		Kernel: kernel,
		Lists: func(p route.Provider) ([]lists.Entry, error) {
			switch p.URL {
			case "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.list":
				return []lists.Entry{{Kind: lists.DomainSuffix, Value: "cn"}, {Kind: lists.DomainSuffix, Value: "tg-cdn.example"}}, nil
			case "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.list":
				return []lists.Entry{{Kind: lists.IPCIDR, Value: "1.0.1.0/24"}}, nil
			}
			return nil, errors.New("no such list")
		},
		Resolve: func(host string) ([]netip.Addr, error) {
			switch host {
			case "tg-cdn.example":
				return []netip.Addr{netip.MustParseAddr("149.154.167.1")}, nil
			case "cn-ip.example":
				return []netip.Addr{netip.MustParseAddr("1.0.1.5")}, nil
			case "lan-host.example":
				return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil
			case "fake.example":
				return []netip.Addr{netip.MustParseAddr("198.18.0.7")}, nil
			}
			return nil, errors.New("NXDOMAIN")
		},
	}
}

func TestExplain(t *testing.T) {
	tests := []struct {
		name     string
		q        Query
		kernel   string
		target   string
		key      string // matched rule's origin key; "" for the default route
		shadowed int
		resolved bool
	}{
		{"most specific entry wins", Query{Host: "mail.google.com"}, "", "DIRECT", "mail.google.com", 1, false},
		{"parent domain", Query{Host: "www.google.com"}, "", "A", "google.com", 0, false},
		{"rule list", Query{Host: "www.example.cn"}, "", "DIRECT", "geosite:cn", 0, false},
		{"ip literal", Query{Host: "149.154.167.50"}, "", "B", "149.154.160.0/20", 0, false},
		{"app entry", Query{Host: "x.example", Process: "/usr/bin/Telegram"}, "", "B", "app:Telegram", 0, false},
		{"default after resolving", Query{Host: "unknown.example"}, "", "G", "default", 0, false},
		{"geoip after resolving", Query{Host: "cn-ip.example"}, "", "DIRECT", "geoip:cn", 0, true},
		// tg-cdn.example is in geosite:cn but resolves into the
		// resolve: true entry. mihomo tries IP entries first...
		{"mihomo: resolving IP entry beats a later list", Query{Host: "tg-cdn.example"}, "", "B", "149.154.160.0/20", 1, true},
		// ...xray matches every domain rule before resolving.
		{"xray: domain list beats IP entry", Query{Host: "tg-cdn.example"}, "xray", "DIRECT", "geosite:cn", 0, false},
		{"xray: default route when nothing matches", Query{Host: "unknown.example"}, "xray", "G", "", 0, false},
		// The resolve: true entry resolved the name, and in mihomo a
		// no-resolve rule does match an IP that an earlier rule resolved.
		{"no-resolve sees an already resolved IP", Query{Host: "lan-host.example"}, "", "DIRECT", "lan", 0, true},
		// sing-box resolves from the resolve: true entry on, so it also
		// beats the list, and the IP rules after it see the address.
		{"sing-box: resolving IP entry beats a later list", Query{Host: "tg-cdn.example"}, "sing-box", "B", "149.154.160.0/20", 1, true},
		{"sing-box: IP rules after the resolving entry", Query{Host: "lan-host.example"}, "sing-box", "DIRECT", "lan", 0, true},
		{"sing-box: geoip after resolving", Query{Host: "cn-ip.example"}, "sing-box", "DIRECT", "geoip:cn", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ex := explainer(t, profile, tt.kernel).Explain(tt.q)
			key := ""
			if ex.Matched != nil {
				key = ex.Matched.Rule.Origin.Key
			}
			if ex.Target != tt.target || key != tt.key || len(ex.Shadowed) != tt.shadowed || ex.AfterResolve != tt.resolved {
				t.Errorf("got target %q via %q, %d shadowed, resolved=%v; want %q via %q, %d, %v",
					ex.Target, key, len(ex.Shadowed), ex.AfterResolve, tt.target, tt.key, tt.shadowed, tt.resolved)
			}
		})
	}
}

// Without any earlier rule that resolves, a no-resolve entry never makes a
// name resolve: lan-host.example resolves to 10.0.0.5 but is not lan.
func TestNoResolveIgnoresNames(t *testing.T) {
	src := `
nodes:
  - { name: A, type: socks5, server: 192.0.2.1, port: 1 }
routes:
  default: A
  lists:
    - { list: geoip:cn, via: DIRECT }
`
	ex := explainer(t, src, "").Explain(Query{Host: "lan-host.example"})
	if ex.Target != "A" || ex.Matched.Rule.Origin.Key != "default" || !ex.AfterResolve {
		t.Errorf("got %q via %+v (resolved %v), want the default route", ex.Target, ex.Matched, ex.AfterResolve)
	}
}

// Without an IP entry that resolves, sing-box never resolves names, so an
// IP list only matches IP addresses; mihomo resolves for the list.
func TestSingBoxResolvesOnlyForResolvingEntries(t *testing.T) {
	src := `
nodes:
  - { name: A, type: socks5, server: 192.0.2.1, port: 1 }
routes:
  default: A
  lists:
    - { list: geoip:cn, via: DIRECT }
`
	if ex := explainer(t, src, "").Explain(Query{Host: "cn-ip.example"}); ex.Target != "DIRECT" {
		t.Errorf("mihomo: got %q, want DIRECT through geoip:cn", ex.Target)
	}
	ex := explainer(t, src, "sing-box").Explain(Query{Host: "cn-ip.example"})
	if ex.Target != "A" || ex.AfterResolve || len(ex.Uncertain) > 0 {
		t.Errorf("sing-box: got %q (resolved %v, uncertain %v), want the default route without resolving", ex.Target, ex.AfterResolve, ex.Uncertain)
	}
	if ex := explainer(t, src, "sing-box").Explain(Query{Host: "1.0.1.9"}); ex.Target != "DIRECT" {
		t.Errorf("sing-box: an IP address got %q, want DIRECT through geoip:cn", ex.Target)
	}
}

// Under TUN the system's DNS answers with fake addresses: they must not
// be matched as if they were where the name is.
func TestFakeIPIsNotAnAnswer(t *testing.T) {
	ex := explainer(t, profile, "").Explain(Query{Host: "fake.example"})
	if len(ex.Resolved) > 0 {
		t.Errorf("resolved = %v, want nothing", ex.Resolved)
	}
	var note string
	for _, h := range ex.Uncertain {
		if h.Rule.Origin.Key == "149.154.160.0/20" {
			note = h.Note
		}
	}
	if !strings.Contains(note, "fake-ip") {
		t.Errorf("note on the IP entry = %q, want it to say the answer was fake", note)
	}
}

func TestListNotDownloaded(t *testing.T) {
	e := explainer(t, profile, "")
	e.Lists = func(p route.Provider) ([]lists.Entry, error) {
		return nil, fmt.Errorf("规则列表 %s %w（离线模式）", p.URL, lists.ErrNotCached)
	}
	ex := e.Explain(Query{Host: "www.example.cn"})
	if len(ex.Uncertain) == 0 || !strings.Contains(ex.Uncertain[len(ex.Uncertain)-1].Note, "还没有下载") {
		t.Errorf("uncertain = %+v, want the lists, not downloaded yet", ex.Uncertain)
	}
}

func TestUncertain(t *testing.T) {
	e := explainer(t, profile, "")
	ex := e.Explain(Query{Host: "x.example"})
	var keys []string
	for _, h := range ex.Uncertain {
		keys = append(keys, h.Rule.Origin.Key)
	}
	// Without a process name the app entry cannot be decided.
	if len(keys) == 0 || keys[0] != "app:Telegram" {
		t.Errorf("uncertain = %q, want the app entry first", keys)
	}
	e.Resolve = nil
	ex = e.Explain(Query{Host: "x.example"})
	found := false
	for _, h := range ex.Uncertain {
		found = found || h.Rule.Origin.Key == "149.154.160.0/20"
	}
	if !found {
		t.Error("without a resolver, rules needing an IP must be uncertain")
	}
}

func TestModes(t *testing.T) {
	ex := explainer(t, profile+"mode: global\n", "").Explain(Query{Host: "mail.google.com"})
	if ex.Target != compile.GlobalGroup || ex.Matched != nil {
		t.Errorf("global mode: %+v", ex)
	}
}

// What users type into `route get` and the "这个地址怎么走" box.
func TestParseQuery(t *testing.T) {
	for in, want := range map[string]Query{
		"google.com":                        {Host: "google.com"},
		" 1.1.1.1 ":                         {Host: "1.1.1.1"},
		"example.com:8443":                  {Host: "example.com", Port: 8443},
		"[2001:db8::1]:53":                  {Host: "2001:db8::1", Port: 53},
		"https://www.youtube.com/watch?v=x": {Host: "www.youtube.com", Port: 443},
		"http://example.com/a":              {Host: "example.com", Port: 80},
		"socks5://192.0.2.1:1080":           {Host: "192.0.2.1", Port: 1080},
	} {
		if got := ParseQuery(in); got != want {
			t.Errorf("ParseQuery(%q) = %+v, want %+v", in, got, want)
		}
	}
}
