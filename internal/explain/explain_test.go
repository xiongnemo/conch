package explain

import (
	"errors"
	"net/netip"
	"testing"

	"nautilus/internal/compile"
	"nautilus/internal/lists"
	"nautilus/internal/model"
	"nautilus/internal/route"
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

func explainer(t *testing.T, src string, xray bool) *Explainer {
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
		Xray:   xray,
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
			}
			return nil, errors.New("NXDOMAIN")
		},
	}
}

func TestExplain(t *testing.T) {
	tests := []struct {
		name     string
		q        Query
		xray     bool
		target   string
		key      string // matched rule's origin key; "" for the default route
		shadowed int
		resolved bool
	}{
		{"most specific entry wins", Query{Host: "mail.google.com"}, false, "DIRECT", "mail.google.com", 1, false},
		{"parent domain", Query{Host: "www.google.com"}, false, "A", "google.com", 0, false},
		{"rule list", Query{Host: "www.example.cn"}, false, "DIRECT", "geosite:cn", 0, false},
		{"ip literal", Query{Host: "149.154.167.50"}, false, "B", "149.154.160.0/20", 0, false},
		{"app entry", Query{Host: "x.example", Process: "/usr/bin/Telegram"}, false, "B", "app:Telegram", 0, false},
		{"default after resolving", Query{Host: "unknown.example"}, false, "G", "default", 0, false},
		{"geoip after resolving", Query{Host: "cn-ip.example"}, false, "DIRECT", "geoip:cn", 0, true},
		// tg-cdn.example is in geosite:cn but resolves into the
		// resolve: true entry. mihomo tries IP entries first...
		{"mihomo: resolving IP entry beats a later list", Query{Host: "tg-cdn.example"}, false, "B", "149.154.160.0/20", 1, true},
		// ...xray matches every domain rule before resolving.
		{"xray: domain list beats IP entry", Query{Host: "tg-cdn.example"}, true, "DIRECT", "geosite:cn", 0, false},
		{"xray: default route when nothing matches", Query{Host: "unknown.example"}, true, "G", "", 0, false},
		// The resolve: true entry resolved the name, and in mihomo a
		// no-resolve rule does match an IP that an earlier rule resolved.
		{"no-resolve sees an already resolved IP", Query{Host: "lan-host.example"}, false, "DIRECT", "lan", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ex := explainer(t, profile, tt.xray).Explain(tt.q)
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
	ex := explainer(t, src, false).Explain(Query{Host: "lan-host.example"})
	if ex.Target != "A" || ex.Matched.Rule.Origin.Key != "default" || !ex.AfterResolve {
		t.Errorf("got %q via %+v (resolved %v), want the default route", ex.Target, ex.Matched, ex.AfterResolve)
	}
}

func TestUncertain(t *testing.T) {
	e := explainer(t, profile, false)
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
	ex := explainer(t, profile+"mode: global\n", false).Explain(Query{Host: "mail.google.com"})
	if ex.Target != compile.GlobalGroup || ex.Matched != nil {
		t.Errorf("global mode: %+v", ex)
	}
}
