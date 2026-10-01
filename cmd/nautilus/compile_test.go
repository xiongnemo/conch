package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"nautilus/internal/daemon"
)

// The CLI compiles what the daemon compiles, so `route get`, `route list`
// and `compile` see the routes added with `route add` too.
func TestPipelineIncludesManaged(t *testing.T) {
	t.Setenv("NAUTILUS_DATA_DIR", t.TempDir())
	profile := filepath.Join(t.TempDir(), "profile.yaml")
	os.WriteFile(profile, []byte("nodes:\n  - { name: A, type: socks5, server: 192.0.2.1, port: 1 }\nroutes:\n  default: DIRECT\n"), 0o644)
	if err := daemon.AddManagedRoute(profile, "example.org", "A"); err != nil {
		t.Fatal(err)
	}
	pl := pipeline{profilePath: profile, offline: true, log: io.Discard}
	res, diags, err := pl.compile(context.Background())
	if err != nil || diags.HasErrors() {
		t.Fatal(err, diags)
	}
	for _, r := range res.Rules {
		if r.Origin.Key == "example.org" && r.Target == "A" {
			return
		}
	}
	t.Errorf("example.org from managed.yaml is not routed: %+v", res.Rules)
}
