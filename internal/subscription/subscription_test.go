package subscription

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/xiongnemo/conch/internal/compile"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/xiongnemo/conch/internal/diag"
	"github.com/xiongnemo/conch/internal/model"
)

const links = "trojan://p@t.example.com:443?sni=t.example.com#香港 01\nss://YWVzLTEyOC1nY206cA@1.2.3.4:8388#日本 01\nvless://u@h:443?weird=1#x\n"

func names(nodes []*model.Node) []string {
	var out []string
	for _, n := range nodes {
		out = append(out, n.Name)
	}
	return out
}

func TestParseFormats(t *testing.T) {
	for name, body := range map[string]string{
		"plain links":  links,
		"base64 links": base64.StdEncoding.EncodeToString([]byte(links)),
	} {
		snap, err := Parse([]byte(body), nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(snap.Nodes) != 3 || len(snap.Warnings) != 1 || !strings.Contains(snap.Warnings[0], "weird") {
			t.Errorf("%s: %d nodes, warnings %q", name, len(snap.Nodes), snap.Warnings)
		}
	}
	for _, bad := range []string{"", "<html>blocked</html>", "proxies: []", "just some text"} {
		if _, err := Parse([]byte(bad), nil); err == nil {
			t.Errorf("Parse(%q) succeeded, want error", bad)
		}
	}
}

func airport(t *testing.T) *Snapshot {
	t.Helper()
	body, err := os.ReadFile("../backend/testdata/subs/airport-a.yaml")
	if err != nil {
		t.Fatal(err)
	}
	snap, err := Parse(body, func(url string) ([]byte, error) {
		return os.ReadFile(filepath.Join("../backend/testdata/subs", filepath.Base(url)))
	})
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func TestApply(t *testing.T) {
	p, err := model.Parse([]byte(`
subscriptions:
  - { name: airport-a, url: "https://example.com/sub", import: [rules], exclude: 剩余流量 }
nodes:
  - { name: home, type: socks5, server: 192.0.2.1, port: 1080 }
`), "profile.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var d diag.List
	Apply(p, map[string]*Snapshot{"airport-a": airport(t)}, &d)
	if len(d) != 0 {
		t.Fatalf("unexpected diagnostics: %v", d)
	}
	wantNodes := []string{"home", "🇭🇰 香港 01", "🇭🇰 香港 02", "🇯🇵 日本 01", "airport-a/home", "[扩展] 香港 IEPL"}
	if got := names(p.Nodes); !slices.Equal(got, wantNodes) {
		t.Errorf("nodes = %q, want %q (filtered, conflict renamed, provider inlined)", got, wantNodes)
	}
	if model.WeakString(model.Lookup(p.Nodes[4].Raw, "name")) != "airport-a/home" {
		t.Error("the renamed node's raw mapping must carry its new name")
	}
	groups := map[string][]string{}
	for _, g := range p.Groups {
		groups[g.Name] = g.Members
	}
	if !slices.Equal(groups["香港节点"], []string{"[扩展] 香港 IEPL", "🇭🇰 香港 01", "🇭🇰 香港 02"}) {
		t.Errorf("use + include-all + filter = %q", groups["香港节点"])
	}
	if len(p.Chains) != 1 || p.Chains[0].Name != "中转" || !slices.Equal(p.Chains[0].Hops, []string{"🇭🇰 香港 01", "🇯🇵 日本 01"}) {
		t.Errorf("relay group should become a chain, got %+v", p.Chains)
	}
	imp := p.Routes.Imported["airport-a"]
	if imp == nil || len(imp.Lines) != 9 || imp.Providers["streaming"].Name != "airport-a-streaming" {
		t.Fatalf("imported rules = %+v", imp)
	}
	if len(p.Routes.Lists) != 1 || p.Routes.Lists[0].List != "airport-a" {
		t.Errorf("imported rules must be appended to the lists, got %+v", p.Routes.Lists)
	}
}

func TestApplyImportLevels(t *testing.T) {
	p, _ := model.Parse([]byte("subscriptions:\n  - { name: a, url: x }\n"), "p.yaml")
	var d diag.List
	Apply(p, map[string]*Snapshot{"a": airport(t)}, &d)
	if len(p.Groups) != 0 || p.Routes.Imported != nil || len(p.Nodes) != 6 {
		t.Errorf("default import is nodes only: %d nodes, %d groups, imported %v", len(p.Nodes), len(p.Groups), p.Routes.Imported)
	}
}

func TestEmptyGroupFailsClosed(t *testing.T) {
	p, _ := model.Parse([]byte("subscriptions:\n  - { name: a, url: x, import: [groups], filter: 日本 }\n"), "p.yaml")
	var d diag.List
	Apply(p, map[string]*Snapshot{"a": airport(t)}, &d)
	for _, g := range p.Groups {
		if g.Name == "香港节点" && !slices.Equal(g.Members, []string{"REJECT"}) {
			t.Errorf("a group emptied by filters must reject, not go direct: %q", g.Members)
		}
	}
	if !slices.ContainsFunc(d, func(x diag.Diagnostic) bool {
		return strings.Contains(x.Msg, "香港节点") && strings.Contains(x.Msg, "屏蔽")
	}) {
		t.Errorf("want a warning about the emptied group, got %v", d)
	}
}

func TestStore(t *testing.T) {
	var body atomic.Value
	body.Store(links)
	var ua atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua.Store(r.Header.Get("User-Agent"))
		w.Header().Set("Subscription-Userinfo", "upload=10; download=20; total=1000; expire=1767225600")
		w.Header().Set("Profile-Update-Interval", "12")
		w.Write([]byte(body.Load().(string)))
	}))
	defer srv.Close()
	sub := &model.Subscription{Name: "s", URL: srv.URL}
	ctx := context.Background()

	offline := &Store{Dir: t.TempDir(), Offline: true}
	if _, _, err := offline.Load(ctx, sub); err == nil {
		t.Fatal("offline store must not download")
	}

	s := &Store{Dir: t.TempDir()}
	snap, info, err := s.Load(ctx, sub)
	if err != nil || len(snap.Nodes) != 3 {
		t.Fatalf("Load = %v, %v", snap, err)
	}
	if ua.Load() != DefaultUserAgent {
		t.Errorf("User-Agent = %v", ua.Load())
	}
	if info.Upload != 10 || info.Download != 20 || info.Total != 1000 || info.Expire != 1767225600 || info.UpdateInterval != 12 {
		t.Errorf("info = %+v", info)
	}

	// A provider outage page must not replace the cache.
	body.Store("<html>维护中</html>")
	if _, _, err := s.Update(ctx, sub); err == nil {
		t.Fatal("Update accepted an HTML page")
	}
	if snap, info, err := s.Load(ctx, sub); err != nil || len(snap.Nodes) != 3 || info.Total != 1000 {
		t.Fatalf("cache was damaged: %v, %+v, %v", snap, info, err)
	}
}

// A few hundred bytes of nested aliases stand for millions of nodes: the
// subscription is refused instead of eating the memory.
func TestAliasBomb(t *testing.T) {
	body := "a: &a [x, x, x, x, x, x, x, x, x, x]\n"
	prev := "a"
	for _, name := range []string{"b", "c", "d", "e", "f", "g", "h"} {
		body += fmt.Sprintf("%s: &%s [*%s, *%s, *%s, *%s, *%s, *%s, *%s, *%s, *%s, *%s]\n", name, name, prev, prev, prev, prev, prev, prev, prev, prev, prev, prev)
		prev = name
	}
	body += "proxies:\n  - { name: n, type: socks5, server: 192.0.2.1, port: 1, bomb: *h }\n"
	if len(body) > 1000 {
		t.Fatalf("the bomb is %d bytes", len(body))
	}
	if _, err := Parse([]byte(body), nil); err == nil || !strings.Contains(err.Error(), "太大") {
		t.Errorf("Parse = %v, want it refused", err)
	}
}

// Nodes a provider got wrong are left out with a warning; the rest of
// the subscription, and the profile, keep working.
func TestBrokenNodesAreSkipped(t *testing.T) {
	snap, err := Parse([]byte(`proxies:
  - { name: good, type: socks5, server: 192.0.2.1, port: 1 }
  - { type: socks5, server: 192.0.2.2, port: 1 }
  - { name: typeless, server: 192.0.2.3, port: 1 }
  - { name: "good ", type: socks5, server: 192.0.2.4, port: 1 }
proxy-groups:
  - { name: G, type: select, proxies: [good, "good "] }
`), nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := model.Parse([]byte("subscriptions:\n  - { name: s, url: https://example.com/s, import: [nodes, groups] }\nroutes:\n  default: G\n"), "profile.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var d diag.List
	Apply(p, map[string]*Snapshot{"s": snap}, &d)
	res := compile.Compile(p)
	if res.Diags.HasErrors() || d.HasErrors() {
		t.Fatalf("compile: %v %v", d, res.Diags)
	}
	if n := len(p.Nodes); n != 2 {
		t.Errorf("%d nodes kept, want good and a renamed second good", n)
	}
	if !strings.Contains(fmt.Sprint(d), "没有名字") || !strings.Contains(fmt.Sprint(d), "没有写 type") {
		t.Errorf("warnings: %v", d)
	}
}

// A node dialing through another keeps doing so when that one is renamed
// for clashing with the profile.
func TestDialerProxyFollowsRename(t *testing.T) {
	snap, err := Parse([]byte(`proxies:
  - { name: hop, type: socks5, server: 192.0.2.1, port: 1 }
  - { name: exit, type: socks5, server: 192.0.2.2, port: 1, dialer-proxy: hop }
`), nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := model.Parse([]byte("subscriptions:\n  - { name: s, url: https://example.com/s }\nnodes:\n  - { name: hop, type: socks5, server: 198.51.100.1, port: 1 }\nroutes:\n  default: DIRECT\n"), "profile.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var d diag.List
	Apply(p, map[string]*Snapshot{"s": snap}, &d)
	for _, n := range p.Nodes {
		if n.Name == "exit" && n.View.DialerProxy != "s/hop" {
			t.Errorf("exit dials through %q, want the renamed s/hop", n.View.DialerProxy)
		}
	}
	if res := compile.Compile(p); res.Diags.HasErrors() {
		t.Error(res.Diags)
	}
}

// A proxy-provider's override sets node settings and renames, as mihomo's
// does, after types and names are filtered on the names as given.
func TestProviderOverride(t *testing.T) {
	snap, err := Parse([]byte(`
proxies: []
proxy-providers:
  p:
    type: inline
    exclude-type: http|socks5
    filter: "HK"
    dialer-proxy: 中转
    override:
      tfo: true
      udp: false
      skip-cert-verify: true
      ip-version: ipv4
      up: "50 Mbps"
      proxy-name: [{ pattern: "^HK-(\\d+)$", target: "香港 $1" }]
      additional-prefix: "[P] "
      override-expr: [".tfo = false"]
    payload:
      - { name: HK-01, type: trojan, server: 192.0.2.1, port: 443, password: p }
      - { name: HK-02, type: socks5, server: 192.0.2.2, port: 1080 }
      - { name: JP-01, type: trojan, server: 192.0.2.3, port: 443, password: p }
`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Nodes) != 1 {
		t.Fatalf("nodes %d, want HK-01 alone", len(snap.Nodes))
	}
	n := snap.Nodes[0]
	for key, want := range map[string]string{"name": "[P] 香港 01", "tfo": "true", "udp": "false", "skip-cert-verify": "true",
		"ip-version": "ipv4", "up": "50 Mbps", "dialer-proxy": "中转"} {
		if got := model.WeakString(model.Lookup(n, key)); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if !strings.Contains(strings.Join(snap.Warnings, "\n"), "override-expr") {
		t.Errorf("override-expr not said: %q", snap.Warnings)
	}
}

// Imported groups get their members as mihomo does and keep its options.
func TestImportedGroupOptions(t *testing.T) {
	snap, err := Parse([]byte(`
proxies:
  - { name: 香港 01, type: trojan, server: s, port: 1, password: p }
  - { name: 香港 02, type: socks5, server: s, port: 2 }
  - { name: 日本 01, type: trojan, server: s, port: 3, password: p }
proxy-providers:
  p:
    type: inline
    payload:
      - { name: 美国 01, type: trojan, server: s, port: 4, password: p }
      - { name: 美国 02, type: trojan, server: s, port: 5, password: p }
proxy-groups:
  - { name: 列出的也排除, type: select, proxies: [香港 01, 日本 01], exclude-filter: 日本 }
  - { name: 全部, type: url-test, include-all: true, filter: "美国`+"`"+`香港", exclude-type: socks5, timeout: 3000, hidden: true }
  - { name: 空的, type: select, proxies: [日本 01], exclude-filter: 日本, empty-fallback: DIRECT }
`), nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := model.Parse([]byte("subscriptions:\n  - { name: s, url: \"https://example.com\", import: [nodes, groups] }\n"), "profile.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var d diag.List
	Apply(p, map[string]*Snapshot{"s": snap}, &d)
	groups := map[string]*model.Group{}
	for _, g := range p.Groups {
		groups[g.Name] = g
	}
	for name, want := range map[string][]string{
		"列出的也排除": {"香港 01"},
		"全部":     {"美国 01", "美国 02", "香港 01"}, // the filters' order; socks5 left out
		"空的":     {"DIRECT"},
	} {
		if g := groups[name]; g == nil || !slices.Equal(g.Members, want) {
			t.Errorf("%s = %v, want %q", name, g, want)
		}
	}
	if g := groups["全部"]; g == nil || g.Timeout != 3000 || !g.Hidden {
		t.Errorf("options: %+v", g)
	}
}
