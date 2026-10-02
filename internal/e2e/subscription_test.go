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

	"github.com/xiongnemo/conch/internal/daemon"
)

// A subscription the machine cannot reach (here its name only resolves on
// the proxy) does not keep a profile that works without it from running,
// and is then downloaded through the kernel.
func TestSubscriptionThroughKernel(t *testing.T) {
	hopBin := hopServerBin(t)
	for _, c := range clients() {
		t.Run(c.name, func(t *testing.T) { testSubscriptionThroughKernel(t, hopBin, c) })
	}
}

func testSubscriptionThroughKernel(t *testing.T, hopBin string, c client) {
	sub := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "proxies:\n  - { name: 订阅节点, type: socks5, server: 127.0.0.1, port: 1 }\n")
	})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go sub.Serve(ln)
	t.Cleanup(func() { sub.Close() })

	hopPort := freePort(t)
	start(t, "hop", hopBin, "config.yaml", fmt.Sprintf(`
mode: direct
log-level: info
hosts: { sub.test: 127.0.0.1 }
listeners:
  - { name: in, type: socks, listen: 127.0.0.1, port: %d }
`, hopPort), mihomoArgs, hopPort)

	dir := t.TempDir()
	profile := filepath.Join(dir, "profile.yaml")
	os.WriteFile(profile, []byte(fmt.Sprintf(`
subscriptions:
  - { name: s, url: "http://sub.test:%d/sub", import: [nodes] }
nodes:
  - { name: A, type: socks5, server: 127.0.0.1, port: %d }
routes:
  default: A
inbound: { mixed-port: %d }
`, ln.Addr().(*net.TCPAddr).Port, hopPort, freePort(t))), 0o644)
	d, err := daemon.New(daemon.Options{ProfilePath: profile, DataDir: filepath.Join(dir, "data"), Backend: c.name, KernelBin: c.bin})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { d.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, "the kernel to run without the subscription", func() bool { return d.Status().Ready })

	if err := d.UpdateSubscription(ctx, "s"); err != nil {
		t.Fatalf("updating through the kernel: %v", err)
	}
	var names []string
	for _, o := range d.Outbounds(ctx) {
		names = append(names, o.Name)
	}
	if !strings.Contains(strings.Join(names, " "), "订阅节点") {
		t.Errorf("outbounds %q lack the subscription's node", names)
	}
}
