//go:build linux

package e2e

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xiongnemo/conch/internal/daemon"
)

// TestTUN turns TUN on and checks that a program that knows nothing of
// the proxy goes through it: the kernel answers its DNS (fake IPs) and its
// connections follow the routing table, through one hop and through a
// chain; with TUN off they no longer do. For xray, which only brings the
// device up, conch routes the system into it. TUN takes over the routing of the
// network it runs in, so the test only runs as root in a network namespace
// of its own that has nothing but a local address (see ci.yml):
//
//	CONCH_TUN_TEST=10.200.0.2 (the namespace's address)
func TestTUN(t *testing.T) {
	addr := os.Getenv("CONCH_TUN_TEST")
	if addr == "" {
		t.Skip("CONCH_TUN_TEST not set: needs root in a network namespace of its own")
	}
	hopBin := hopServerBin(t)
	for _, c := range clients() {
		t.Run(c.name, func(t *testing.T) { testTUN(t, addr, hopBin, c) })
	}
}

func testTUN(t *testing.T, addr, hopBin string, c client) {
	// Everything listens on the namespace's address: TUN leaves loopback alone.
	echo := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })}
	ln, err := net.Listen("tcp", net.JoinHostPort(addr, "0"))
	if err != nil {
		t.Fatal(err)
	}
	go echo.Serve(ln)
	t.Cleanup(func() { echo.Close() })
	echoPort := ln.Addr().(*net.TCPAddr).Port

	hop := func(name string) (*kernel, int) {
		port := freePort(t)
		return startOn(t, name, hopBin, fmt.Sprintf(`
mode: direct
log-level: info
hosts: { echo.test: %[1]s, echo2.test: %[1]s }
listeners:
  - { name: in, type: socks, listen: %[1]s, port: %[2]d, udp: true }
`, addr, port), net.JoinHostPort(addr, fmt.Sprint(port))), port
	}
	hopA, portA := hop("hopA")
	hopB, portB := hop("hopB")

	dir := t.TempDir()
	profile := filepath.Join(dir, "profile.yaml")
	os.WriteFile(profile, []byte(fmt.Sprintf(`
nodes:
  - { name: A, type: socks5, server: %[1]s, port: %[2]d, udp: true }
  - { name: B, type: socks5, server: %[1]s, port: %[3]d, udp: true }
chains:
  AB: [A, B]
routes:
  default: DIRECT
  entries:
    echo.test: A
    echo2.test: AB
inbound: { mixed-port: %[4]d }
`, addr, portA, portB, freePort(t))), 0o644)

	d, err := daemon.New(daemon.Options{ProfilePath: profile, DataDir: filepath.Join(dir, "data"), Backend: c.name, KernelBin: c.bin, Offline: true})
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
			t.Logf("--- daemon kernel log ---\n%s", strings.Join(d.Logs(), "\n"))
		}
	})
	waitFor(t, "the daemon", func() bool { return d.Status().Ready })
	if err := d.SetTUN(ctx, true); err != nil {
		t.Fatal(err)
	}

	// No proxy: the system resolver and routes, as any program has them.
	get := func(host string) string {
		client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 3 * time.Second}
		resp, err := client.Get(fmt.Sprintf("http://%s:%d/", host, echoPort))
		if err != nil {
			return err.Error()
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return string(body)
	}
	waitFor(t, "echo.test through TUN and A", func() bool { return get("echo.test") == "ok" })
	if !strings.Contains(hopA.out.String(), fmt.Sprintf("echo.test:%d", echoPort)) {
		t.Errorf("A did not carry echo.test:\n%s", hopA.out)
	}
	if got := get("echo2.test"); got != "ok" {
		t.Fatalf("echo2.test through the chain: %s", got)
	}
	waitFor(t, "A to forward to B and B to reach echo2.test", func() bool {
		return strings.Contains(hopA.out.String(), fmt.Sprintf(":%d", portB)) && strings.Contains(hopB.out.String(), fmt.Sprintf("echo2.test:%d", echoPort))
	})

	if err := d.SetTUN(ctx, false); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "echo.test to stop resolving without TUN", func() bool { return get("echo.test") != "ok" })
}

// startOn is start for a kernel that listens on addr instead of loopback.
func startOn(t *testing.T, name, bin, config, addr string) *kernel {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(config), 0o600)
	k := &kernel{name: name, out: &syncBuffer{}}
	cmd := exec.Command(bin, mihomoArgs(dir, path)...)
	cmd.Stdout, cmd.Stderr = k.out, k.out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			t.Logf("--- %s output ---\n%s", name, k.out)
		}
	})
	waitFor(t, name+" to listen on "+addr, func() bool {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
		}
		return err == nil
	})
	return k
}
