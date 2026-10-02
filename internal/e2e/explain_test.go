package e2e

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/xiongnemo/conch/internal/daemon"
	"github.com/xiongnemo/conch/internal/explain"
)

// Explanations look names up with the kernel's DNS, which can answer
// differently from the system's (under TUN it always does): a name only
// the kernel's DNS server knows must resolve, into the IP entry it is in.
func TestExplainUsesKernelDNS(t *testing.T) {
	want := netip.MustParseAddr("192.0.2.7")
	ns := fakeDNS(t, "kernel-only.test", want)
	for _, c := range clients() {
		if c.name == "xray" {
			continue // xray cannot look names up for others: the system's DNS is used
		}
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			profile := filepath.Join(dir, "profile.yaml")
			os.WriteFile(profile, []byte(fmt.Sprintf(`
nodes:
  - { name: A, type: socks5, server: 127.0.0.1, port: 1 }
routes:
  default: DIRECT
  entries:
    192.0.2.0/24: { via: A, resolve: true }
dns: { enable: true, nameservers: ["udp://%s"] }
inbound: { mixed-port: %d }
`, ns, freePort(t))), 0o644)
			d, err := daemon.New(daemon.Options{ProfilePath: profile, DataDir: filepath.Join(dir, "data"), Backend: c.name, KernelBin: c.bin, Offline: true})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { d.Run(ctx); close(done) }()
			t.Cleanup(func() { cancel(); <-done })
			waitFor(t, "the daemon", func() bool { return d.Status().Ready })

			ex, err := d.Explain(ctx, explain.Query{Host: "kernel-only.test"})
			if err != nil {
				t.Fatal(err)
			}
			if ex.Target != "A" || len(ex.Resolved) == 0 || ex.Resolved[0] != want {
				t.Errorf("kernel-only.test → %s, resolved %v; want A through 192.0.2.0/24, resolved to %s", ex.Target, ex.Resolved, want)
			}
		})
	}
}

// fakeDNS answers A queries for name with addr over UDP, and NXDOMAIN for
// other names. It returns its address.
func fakeDNS(t *testing.T, name string, addr netip.Addr) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			known := strings.EqualFold(q.Name.String(), name+".")
			reply := dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: h.RecursionDesired, RecursionAvailable: true}
			if !known {
				reply.RCode = dnsmessage.RCodeNameError
			}
			b := dnsmessage.NewBuilder(nil, reply)
			b.StartQuestions()
			b.Question(q)
			b.StartAnswers()
			if known && q.Type == dnsmessage.TypeA {
				b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: addr.As4()})
			}
			if msg, err := b.Finish(); err == nil {
				pc.WriteTo(msg, from)
			}
		}
	}()
	return pc.LocalAddr().String()
}
