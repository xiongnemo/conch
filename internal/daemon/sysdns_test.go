package daemon

import (
	"testing"

	"github.com/xiongnemo/conch/internal/compile"
	"github.com/xiongnemo/conch/internal/platform/sysdns"
)

func swapDNS(t *testing.T) *string {
	resolver := "router"
	oldNeeded, oldEnable, oldRestore := dnsNeeded, enableDNS, restoreDNS
	dnsNeeded = func() bool { return true }
	enableDNS = func(server string) (sysdns.Snapshot, error) {
		prev := resolver
		resolver = server
		return sysdns.Snapshot(prev), nil
	}
	restoreDNS = func(s sysdns.Snapshot) error { resolver = string(s); return nil }
	t.Cleanup(func() { dnsNeeded, enableDNS, restoreDNS = oldNeeded, oldEnable, oldRestore })
	return &resolver
}

func tunDaemon(t *testing.T, tun bool) *Daemon {
	d := testDaemon(t, 7890)
	d.applied = []byte("config")
	d.res = &compile.Result{Settings: compile.Settings{TUN: compile.TUNSettings{Enable: tun},
		DNS: compile.DNSSettings{Nameservers: []string{"https://1.12.12.12/dns-query"}}}}
	return d
}

// While TUN runs, the system resolver points at an address TUN captures;
// it goes back when TUN is off, the daemon stops, or after a crash.
func TestDNSTakeover(t *testing.T) {
	resolver := swapDNS(t)
	d := tunDaemon(t, true)
	d.syncDNS()
	if *resolver != "1.12.12.12" {
		t.Fatalf("with TUN the resolver is %q", *resolver)
	}
	d.syncDNS() // reconciling again must not snapshot conch' own setting
	d.res.Settings.TUN.Enable = false
	d.syncDNS()
	if *resolver != "router" || d.state.DNS != nil {
		t.Fatalf("TUN off: resolver %q, state %+v", *resolver, d.state.DNS)
	}

	d.res.Settings.TUN.Enable = true
	d.syncDNS()
	d.releaseDNS()
	if *resolver != "router" {
		t.Fatalf("after stop: %q", *resolver)
	}

	d.syncDNS() // crash: nothing restores, so doctor --fix does
	if repaired, err := RepairDNS(d.opts.DataDir); !repaired || err != nil || *resolver != "router" {
		t.Errorf("repair: %v %v, resolver %q", repaired, err, *resolver)
	}
}
