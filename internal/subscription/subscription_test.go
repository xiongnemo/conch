package subscription

import (
	"context"
	"encoding/base64"
	"fmt"
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
