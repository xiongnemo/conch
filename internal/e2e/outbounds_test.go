package e2e

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/xiongnemo/conch/internal/api"
	"github.com/xiongnemo/conch/internal/auth"
	"github.com/xiongnemo/conch/internal/daemon"
)

// TestManagedOutbounds adds nodes from share links and builds chains from
// the API, as the Web UI and TUI do, and checks that a change that would
// break the config is refused without touching the running one.
func TestManagedOutbounds(t *testing.T) {
	bin := os.Getenv("CONCH_MIHOMO")
	if bin == "" {
		t.Skip("CONCH_MIHOMO not set")
	}
	dir := t.TempDir()
	profile := filepath.Join(dir, "profile.yaml")
	os.WriteFile(profile, []byte(fmt.Sprintf(`
nodes:
  - { name: home, type: socks5, server: 127.0.0.1, port: 1080 }
routes:
  default: DIRECT
inbound: { mixed-port: %d }
`, freePort(t))), 0o644)
	d, err := daemon.New(daemon.Options{ProfilePath: profile, DataDir: filepath.Join(dir, "data"), Backend: "mihomo", KernelBin: bin, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { d.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, "the daemon", func() bool { return d.Status().Ready })
	guard := auth.NewGuard(auth.Settings{Password: "pw", Auth: true, Listen: auth.DefaultListen})
	srv := httptest.NewServer((&api.Server{D: d, Guard: guard}).Handler())
	t.Cleanup(srv.Close)
	c := &api.Client{Base: srv.URL, Password: "pw", HTTP: srv.Client()}

	name, err := c.AddNode(ctx, "socks://dXNlcjpwYXNz@127.0.0.1:1081#HK 01")
	if err != nil || name != "HK 01" {
		t.Fatalf("add node = %q, %v", name, err)
	}
	// The same name again gets a suffix rather than an error.
	if again, err := c.AddNode(ctx, "socks://127.0.0.1:1082#HK 01"); err != nil || again != "HK 01 (2)" {
		t.Errorf("second node = %q, %v", again, err)
	}
	if err := c.SetChain(ctx, "AI-Exit", []string{"HK 01", "home"}); err != nil {
		t.Fatal(err)
	}
	out, _ := c.Outbounds(ctx)
	i := slices.IndexFunc(out, func(o daemon.Outbound) bool { return o.Name == "AI-Exit" })
	if i < 0 || !out[i].Managed || !slices.Equal(out[i].Hops, []string{"HK 01", "home"}) {
		t.Fatalf("outbounds = %+v", out)
	}
	if j := slices.IndexFunc(out, func(o daemon.Outbound) bool { return o.Name == "home" }); out[j].Managed {
		t.Error("a node from profile.yaml is marked as managed")
	}
	if err := c.SetRoute(ctx, "openai.com", "AI-Exit", 0); err != nil {
		t.Fatal(err)
	}

	// Groups: written to managed.yaml, usable at once, and a chain can start
	// with one.
	var apiErr *api.APIError
	if err := c.SetGroup(ctx, "香港", "url-test", []string{"HK 01", "HK 01 (2)"}); err != nil {
		t.Fatal(err)
	}
	if err := c.SetChain(ctx, "经香港", []string{"香港", "home"}); err != nil {
		t.Fatal(err)
	}
	out, _ = c.Outbounds(ctx)
	g := slices.IndexFunc(out, func(o daemon.Outbound) bool { return o.Name == "香港" })
	if g < 0 || !out[g].Managed || out[g].Type != "url-test" || !slices.Equal(out[g].Members, []string{"HK 01", "HK 01 (2)"}) {
		t.Fatalf("the new group: %+v", out)
	}
	if err := c.SetGroup(ctx, "坏组", "select", []string{"nowhere"}); !errors.As(err, &apiErr) || apiErr.Status != http.StatusUnprocessableEntity {
		t.Errorf("a group with an unknown member: %v", err)
	}
	if err := c.SetGroup(ctx, "home", "select", []string{"HK 01"}); !errors.As(err, &apiErr) || apiErr.Status != http.StatusConflict {
		t.Errorf("a group named like a profile node: %v", err)
	}
	if err := c.DeleteGroup(ctx, "香港"); err == nil {
		t.Error("deleting a group a chain uses must fail")
	}
	if err := c.DeleteChain(ctx, "经香港"); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteGroup(ctx, "香港"); err != nil {
		t.Fatal(err)
	}

	// Breaking changes are refused and leave everything as it was.
	before, _ := os.ReadFile(filepath.Join(dir, "managed.yaml"))
	if err := c.SetChain(ctx, "bad", []string{"HK 01", "nowhere"}); !errors.As(err, &apiErr) || apiErr.Status != http.StatusUnprocessableEntity {
		t.Errorf("chain through an unknown node: %v", err)
	}
	if err := c.DeleteChain(ctx, "AI-Exit"); err == nil {
		t.Error("deleting a chain a route uses must fail")
	}
	if after, _ := os.ReadFile(filepath.Join(dir, "managed.yaml")); string(after) != string(before) {
		t.Errorf("managed.yaml changed by refused edits:\n%s", after)
	}
	if s := d.Status(); s.Error != "" {
		t.Errorf("status error after refused edits: %s", s.Error)
	}
	// profile.yaml is never rewritten.
	if err := c.DeleteNode(ctx, "home"); !errors.As(err, &apiErr) || apiErr.Status != http.StatusConflict || !strings.Contains(apiErr.Body.Where, "profile.yaml") {
		t.Errorf("deleting a profile node: %v", err)
	}
	if err := c.SetChain(ctx, "home", []string{"HK 01", "home"}); !errors.As(err, &apiErr) || apiErr.Status != http.StatusConflict {
		t.Errorf("a chain named like a profile node: %v", err)
	}

	if err := c.DeleteRoute(ctx, "openai.com"); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteChain(ctx, "AI-Exit"); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"HK 01", "HK 01 (2)"} {
		if err := c.DeleteNode(ctx, n); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.DeleteNode(ctx, "HK 01"); !errors.As(err, &apiErr) || apiErr.Status != http.StatusNotFound {
		t.Errorf("deleting a missing node: %v", err)
	}
}

// TestNodesByHand writes nodes as the form and the YAML box do: checked
// before saving, renamed with what managed.yaml points at them, and
// never put in place of profile.yaml's.
func TestNodesByHand(t *testing.T) {
	bin := os.Getenv("CONCH_MIHOMO")
	if bin == "" {
		t.Skip("CONCH_MIHOMO not set")
	}
	dir := t.TempDir()
	profile := filepath.Join(dir, "profile.yaml")
	os.WriteFile(profile, []byte(fmt.Sprintf(`
nodes:
  - { name: home, type: socks5, server: 127.0.0.1, port: 1080 }
routes:
  default: DIRECT
inbound: { mixed-port: %d }
`, freePort(t))), 0o644)
	d, err := daemon.New(daemon.Options{ProfilePath: profile, DataDir: filepath.Join(dir, "data"), Backend: "mihomo", KernelBin: bin, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { d.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, "the daemon", func() bool { return d.Status().Ready })
	guard := auth.NewGuard(auth.Settings{Password: "pw", Auth: true, Listen: auth.DefaultListen})
	srv := httptest.NewServer((&api.Server{D: d, Guard: guard}).Handler())
	t.Cleanup(srv.Close)
	c := &api.Client{Base: srv.URL, Password: "pw", HTTP: srv.Client()}
	form := func(json string) daemon.NodeInput { return daemon.NodeInput{Node: []byte(json)} }

	check, err := c.CheckNodes(ctx, form(`{"type": "socks5", "name": "Hand", "server": "127.0.0.1", "udp": true}`), "")
	if err != nil || len(check.Errors) != 1 || !strings.Contains(check.Errors[0], "还要填：端口") {
		t.Errorf("check without a port: %+v, %v", check, err)
	}
	check, _ = c.CheckNodes(ctx, form(`{"udp": true, "port": 1081, "type": "socks5", "name": "Hand", "server": "127.0.0.1", "sni": ""}`), "")
	if len(check.Errors) > 0 || check.YAML != "{name: Hand, type: socks5, server: 127.0.0.1, port: 1081, udp: true}\n" {
		t.Errorf("check: %+v", check)
	}
	if check, _ = c.CheckNodes(ctx, daemon.NodeInput{YAML: "{ name: home, type: http, server: 127.0.0.1, port: 1 }"}, ""); len(check.Errors) == 0 {
		t.Error("a name profile.yaml has passed the check")
	}

	names, err := c.SaveNodes(ctx, form(`{"name": "Hand", "type": "socks5", "server": "127.0.0.1", "port": 1081}`), "")
	if err != nil || len(names) != 1 || names[0] != "Hand" {
		t.Fatalf("save = %v, %v", names, err)
	}
	if err := c.SetChain(ctx, "经 Hand", []string{"Hand", "home"}); err != nil {
		t.Fatal(err)
	}
	if err := c.SetRoute(ctx, "example.org", "Hand", 0); err != nil {
		t.Fatal(err)
	}

	// Renamed, the chain and the entry go along.
	if _, err := c.SaveNodes(ctx, daemon.NodeInput{YAML: "{ name: Hand 2, type: socks5, server: 127.0.0.1, port: 1082 }"}, "Hand"); err != nil {
		t.Fatal(err)
	}
	managed, _ := os.ReadFile(filepath.Join(dir, "managed.yaml"))
	for _, want := range []string{"{name: Hand 2, type: socks5, server: 127.0.0.1, port: 1082}", "经 Hand: [Hand 2, home]", "example.org: Hand 2"} {
		if !strings.Contains(string(managed), want) {
			t.Errorf("managed.yaml lacks %q:\n%s", want, managed)
		}
	}
	if v, err := c.Node(ctx, "Hand 2"); err != nil || !v.Managed || v.Node["port"] != float64(1082) {
		t.Errorf("node Hand 2 = %+v, %v", v, err)
	}
	if v, err := c.Node(ctx, "home"); err != nil || v.Managed || v.YAML != "{name: home, type: socks5, server: 127.0.0.1, port: 1080}\n" {
		t.Errorf("node home = %+v, %v", v, err)
	}

	var apiErr *api.APIError
	if _, err := c.SaveNodes(ctx, form(`{"name": "home", "type": "socks5", "server": "127.0.0.1", "port": 1}`), "home"); !errors.As(err, &apiErr) || apiErr.Status != http.StatusConflict {
		t.Errorf("editing a profile node: %v", err)
	}
	if _, err := c.SaveNodes(ctx, form(`{"name": "Hand 2", "type": "socks5", "server": "127.0.0.1", "port": 1}`), ""); err == nil || !strings.Contains(err.Error(), "已经有") {
		t.Errorf("a second Hand 2: %v", err)
	}
	// What a link had that the node cannot keep is said.
	if added, err := c.AddNodes(ctx, "vless://11111111-2222-3333-4444-555555555555@127.0.0.1:1090?security=none&custom=1#V1"); err != nil ||
		len(added.Warnings) != 1 || !strings.Contains(added.Warnings[0], "custom") {
		t.Errorf("a link with an unknown parameter: %+v, %v", added, err)
	}
	// Two at once, as YAML.
	if names, err := c.SaveNodes(ctx, daemon.NodeInput{YAML: "- { name: Y1, type: http, server: 127.0.0.1, port: 2 }\n- { name: Y2, type: http, server: 127.0.0.1, port: 3 }\n"}, ""); err != nil || strings.Join(names, ",") != "Y1,Y2" {
		t.Errorf("two nodes = %v, %v", names, err)
	}
}
