package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xiongnemo/conch/internal/daemon"
	"github.com/xiongnemo/conch/internal/kernels"
)

// installAs lays a kernel binary out the way `conch kernel install`
// does, so the daemon finds it by name.
func installAs(t *testing.T, dataDir, kernel, bin string) {
	t.Helper()
	dir := filepath.Join(dataDir, "kernels", kernel, "v0")
	os.MkdirAll(dir, 0o755)
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, kernels.BinaryName(kernel, kernels.Host().OS)), data, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dataDir, "kernels", kernel, "current"), []byte("v0\n"), 0o644)
}

// TestSwitchKernel switches a running daemon from mihomo to sing-box and
// back: the run goes on, with its mode, and a kernel that cannot run the
// profile gives way to the one before.
func TestSwitchKernel(t *testing.T) {
	mihomo, singbox := os.Getenv("CONCH_MIHOMO"), os.Getenv("CONCH_SING_BOX")
	if mihomo == "" || singbox == "" {
		t.Skip("CONCH_MIHOMO or CONCH_SING_BOX not set")
	}
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	installAs(t, data, "mihomo", mihomo)
	installAs(t, data, "sing-box", singbox)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	profile := filepath.Join(dir, "profile.yaml")
	os.WriteFile(profile, []byte(fmt.Sprintf("routes: { default: DIRECT }\ninbound: { mixed-port: %d }\n", port)), 0o644)

	opts := daemon.Options{ProfilePath: profile, DataDir: data, Backend: "mihomo", Offline: true, Log: io.Discard}
	d, err := daemon.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	var live atomic.Pointer[daemon.Daemon]
	live.Store(d)
	switches := make(chan kernelSwitch)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runSwitching(ctx, opts, &live, switches, io.Discard) }()
	t.Cleanup(func() { cancel(); <-done })
	switchTo := func(name string) error {
		sw := kernelSwitch{name: name, done: make(chan error, 1)}
		switches <- sw
		return <-sw.done
	}
	ready := func() daemon.Status {
		t.Helper()
		for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(50 * time.Millisecond) {
			if s := live.Load().Status(); s.Ready {
				return s
			} else if time.Now().After(deadline) {
				t.Fatalf("not ready: %+v", s)
			}
		}
	}
	// Its kernel is a release conch was not verified with, and says so.
	if s := ready(); s.KernelVersion != "v0" || !s.Unverified {
		t.Errorf("an unverified release: %+v", s)
	}
	if err := live.Load().SetMode(ctx, "global"); err != nil {
		t.Fatal(err)
	}
	events, stop := live.Load().Events.Subscribe()
	defer stop()

	if err := switchTo("sing-box"); err != nil {
		t.Fatal(err)
	}
	if s := ready(); s.Backend != "sing-box" || s.Mode != "global" || s.MixedPort != port {
		t.Errorf("after the switch: %+v", s)
	}
	// Clients subscribed before the switch hear the new kernel.
	for deadline := time.After(5 * time.Second); ; {
		select {
		case e := <-events:
			if s, ok := e.Data.(daemon.Status); ok && s.Backend == "sing-box" {
				goto heard
			}
			continue
		case <-deadline:
			t.Fatal("no state event from the new kernel")
		}
	}
heard:
	if c, err := net.DialTimeout("tcp", fmt.Sprint("127.0.0.1:", port), time.Second); err != nil {
		t.Errorf("the proxy port is closed: %v", err)
	} else {
		c.Close()
	}

	// A node sing-box cannot use: the switch to it fails, mihomo stays.
	if err := switchTo("mihomo"); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(profile, []byte(fmt.Sprintf(`nodes:
  - { name: n, type: ss, server: 127.0.0.1, port: 1, cipher: aes-256-gcm-siv, password: p }
routes: { default: n }
inbound: { mixed-port: %d }
`, port)), 0o644)
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		if out := live.Load().Outbounds(ctx); slices.ContainsFunc(out, func(o daemon.Outbound) bool { return o.Name == "n" }) {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("mihomo did not take the profile: %+v", live.Load().Status())
		}
	}
	err = switchTo("sing-box")
	if err == nil || !strings.Contains(err.Error(), "仍在使用 mihomo") || !strings.Contains(err.Error(), "aes-256-gcm-siv") {
		t.Errorf("switch to a kernel that cannot run the profile: %v", err)
	}
	if s := ready(); s.Backend != "mihomo" || s.Mode != "global" {
		t.Errorf("after the failed switch: %+v", s)
	}
	if err := switchTo("nope"); err == nil {
		t.Error("switched to a kernel that does not exist")
	}
}
