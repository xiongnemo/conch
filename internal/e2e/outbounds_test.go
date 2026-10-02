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

	// Breaking changes are refused and leave everything as it was.
	before, _ := os.ReadFile(filepath.Join(dir, "managed.yaml"))
	var apiErr *api.APIError
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
