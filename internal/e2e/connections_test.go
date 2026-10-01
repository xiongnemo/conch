package e2e

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nautilus/internal/daemon"
)

// TestConnectionsAndFailures checks that open connections are explained
// with the entry that routed them, and that failing sites are collected.
func TestConnectionsAndFailures(t *testing.T) {
	bin := os.Getenv("NAUTILUS_MIHOMO")
	if bin == "" {
		t.Skip("NAUTILUS_MIHOMO not set")
	}
	release := make(chan struct{})
	slow := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-time.After(10 * time.Second):
		}
		fmt.Fprint(w, "ok")
	})}
	// 127.0.0.2 is loopback on Linux; a route entry for it is easy to spot.
	ln, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skip("cannot listen on 127.0.0.2:", err)
	}
	go slow.Serve(ln)
	t.Cleanup(func() { close(release); slow.Close() })
	echoPort := ln.Addr().(*net.TCPAddr).Port

	dir := t.TempDir()
	mixed := freePort(t)
	profile := filepath.Join(dir, "profile.yaml")
	os.WriteFile(profile, []byte(fmt.Sprintf(`
nodes:
  - { name: dead, type: socks5, server: 127.0.0.1, port: 1 }
routes:
  default: DIRECT
  entries:
    127.0.0.2: DIRECT
    blocked.example: dead
inbound: { mixed-port: %d }
`, mixed)), 0o644)
	d, err := daemon.New(daemon.Options{ProfilePath: profile, DataDir: filepath.Join(dir, "data"), Backend: "mihomo", KernelBin: bin, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { d.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	for deadline := time.Now().Add(15 * time.Second); !d.Status().Ready; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("daemon not ready")
		}
	}

	go tryGet(mixed, fmt.Sprintf("http://127.0.0.2:%d/slow", echoPort))
	var found *daemon.Connection
	for deadline := time.Now().Add(5 * time.Second); found == nil && time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		conns, err := d.Connections(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for i, c := range conns {
			if c.Host == "127.0.0.2" {
				found = &conns[i]
			}
		}
	}
	if found == nil {
		t.Fatalf("the open connection is not listed; kernel log:\n%s", strings.Join(d.Logs(), "\n"))
	}
	if !strings.Contains(found.Matched, "IP 条目 127.0.0.2") || found.Via[len(found.Via)-1] != "DIRECT" {
		t.Errorf("connection explained as %q via %q", found.Matched, found.Via)
	}

	tryGet(mixed, "http://blocked.example/")
	waitFor(t, "the failure to be recorded", func() bool {
		for _, f := range d.Failed() {
			if f.Host == "blocked.example" && f.Via == "dead" {
				return true
			}
		}
		return false
	})
}
