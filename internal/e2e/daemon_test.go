package e2e

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nautilus/internal/daemon"
)

// TestDaemon drives a daemon through the life of a profile: start, switch
// a group, temporary routes, a broken edit that must not take the proxy
// down, and a fix that is picked up from the file.
func TestDaemon(t *testing.T) {
	hopBin := hopServerBin(t)
	for _, c := range clients() {
		t.Run(c.name, func(t *testing.T) { testDaemon(t, hopBin, c) })
	}
}

func testDaemon(t *testing.T, hopBin string, c client) {
	echo := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go echo.Serve(ln)
	t.Cleanup(func() { echo.Close() })
	echoPort := ln.Addr().(*net.TCPAddr).Port
	target := fmt.Sprintf("echo.test:%d", echoPort)

	hop := func(name string) (*kernel, int) {
		port := freePort(t)
		return start(t, name, hopBin, "config.yaml", fmt.Sprintf(`
mode: direct
log-level: info
hosts: { echo.test: 127.0.0.1 }
listeners:
  - { name: in, type: socks, listen: 127.0.0.1, port: %d, udp: true }
`, port), mihomoArgs, port), port
	}
	hopA, portA := hop("hopA")
	hopB, portB := hop("hopB")
	mixed := freePort(t)

	dir := t.TempDir()
	profile := filepath.Join(dir, "profile.yaml")
	write := func(extra string) {
		t.Helper()
		src := fmt.Sprintf(`
nodes:
  - { name: A, type: socks5, server: 127.0.0.1, port: %d, udp: true }
  - { name: B, type: socks5, server: 127.0.0.1, port: %d, udp: true }
groups:
  - { name: 选择, type: select, members: [A, B] }
routes:
  default: 选择
%s
inbound: { mixed-port: %d }
`, portA, portB, extra, mixed)
		if err := os.WriteFile(profile, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("")

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
	for deadline := time.Now().Add(15 * time.Second); !d.Status().Ready; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("daemon not ready: %+v", d.Status())
		}
	}

	// via reports which hop the next request goes through.
	count := func(k *kernel) int { return strings.Count(k.out.String(), target) }
	via := func(step string) string {
		t.Helper()
		a, b := count(hopA), count(hopB)
		for deadline := time.Now().Add(10 * time.Second); tryGet(mixed, "http://"+target+"/") != "ok"; {
			if time.Now().After(deadline) {
				t.Fatalf("%s: the proxy did not answer", step)
			}
			time.Sleep(100 * time.Millisecond)
		}
		// Hop logs arrive asynchronously.
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
			switch {
			case count(hopA) > a:
				return "A"
			case count(hopB) > b:
				return "B"
			}
		}
		return "DIRECT"
	}

	if got := via("initial"); got != "A" {
		t.Fatalf("initial route goes via %s, want A (the group's first member)", got)
	}
	if err := d.Select(ctx, "选择", "B"); err != nil {
		t.Fatal(err)
	}
	if got := via("after select"); got != "B" {
		t.Fatalf("after selecting B, traffic goes via %s", got)
	}
	if err := d.SetRoute(ctx, "echo.test", "A", time.Hour); err != nil {
		t.Fatal(err)
	}
	if got := via("temporary route"); got != "A" {
		t.Fatalf("temporary route to A, traffic goes via %s", got)
	}
	if err := d.DeleteRoute(ctx, "echo.test"); err != nil {
		t.Fatal(err)
	}
	if got := via("route deleted"); got != "B" {
		t.Fatalf("after deleting the temporary route (selection B), traffic goes via %s", got)
	}

	// A broken edit must keep the last good config running.
	os.WriteFile(profile, []byte("routes: [this is not a profile"), 0o644)
	waitFor(t, "the broken edit to be reported", func() bool { return d.Status().Error != "" })
	if got := via("broken profile"); got != "B" {
		t.Fatalf("with a broken profile, traffic goes via %s; the old config should keep running", got)
	}
	// Fixing the file is picked up without any API call. The selection
	// is still B, so an entry sending the target to A shows the edit applied.
	write("  entries:\n    echo.test: A\n")
	waitFor(t, "the fix to be applied", func() bool { return d.Status().Error == "" })
	if got := via("fixed profile"); got != "A" {
		t.Fatalf("after adding echo.test: A, traffic goes via %s", got)
	}
}

// tryGet fetches target through the proxy, returning "" on any failure.
func tryGet(proxyPort int, target string) string {
	proxy, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}, Timeout: 3 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}
