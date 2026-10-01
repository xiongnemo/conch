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

// TestConnectionsAndFailures checks that connections are explained with
// the entry that routed them, that failing sites are collected and that
// delay tests go through the outbound they name.
func TestConnectionsAndFailures(t *testing.T) {
	cs := clients()
	if len(cs) == 0 {
		t.Skip("NAUTILUS_MIHOMO and NAUTILUS_XRAY not set")
	}
	for _, c := range cs {
		t.Run(c.name, func(t *testing.T) { testConnectionsAndFailures(t, c) })
	}
}

func testConnectionsAndFailures(t *testing.T, c client) {
	release := make(chan struct{})
	slow := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/slow":
			select {
			case <-release:
			case <-time.After(10 * time.Second):
			}
		case "/fast":
			time.Sleep(5 * time.Millisecond) // mihomo reports 0 ms as a failure
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
	d, err := daemon.New(daemon.Options{ProfilePath: profile, DataDir: filepath.Join(dir, "data"), Backend: c.name, KernelBin: c.bin, Offline: true,
		DelayURL: fmt.Sprintf("http://127.0.0.2:%d/fast", echoPort)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { d.Run(ctx); close(done) }()
	t.Cleanup(func() {
		cancel()
		<-done
		if t.Failed() {
			t.Logf("--- kernel log ---\n%s", strings.Join(d.Logs(), "\n"))
		}
	})
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
	if !strings.Contains(found.Matched, "IP 条目 127.0.0.2") || len(found.Via) == 0 || found.Via[len(found.Via)-1] != "DIRECT" {
		t.Errorf("connection explained as %q via %q", found.Matched, found.Via)
	}
	if caps := d.Status().Caps; caps.LiveConnections != (c.name == "mihomo") {
		t.Errorf("caps = %+v", caps)
	}

	if dl, err := d.Delay(ctx, "DIRECT"); err != nil || dl <= 0 {
		t.Errorf("delay through DIRECT = %v, %v", dl, err)
	}
	if _, err := d.Delay(ctx, "dead"); err == nil {
		t.Error("a delay test through a dead node succeeded")
	}
	// Delay tests run in parallel without getting in each other's way.
	errs := make(chan error, 8)
	for i := range 8 {
		go func() {
			name := []string{"DIRECT", "dead"}[i%2]
			_, err := d.Delay(ctx, name)
			if (err == nil) != (name == "DIRECT") {
				err = fmt.Errorf("delay through %s: %v", name, err)
			} else {
				err = nil
			}
			errs <- err
		}()
	}
	for range 8 {
		if err := <-errs; err != nil {
			t.Error(err)
		}
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
