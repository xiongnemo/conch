package daemon

import (
	"io"
	"testing"

	"nautilus/internal/platform/sysproxy"
)

// fakeOS records what the system proxy points at.
type fakeOS struct {
	port     int // 0 = the user's own setting
	restores int
}

func swapSysProxy(t *testing.T) *fakeOS {
	f := &fakeOS{}
	oldEnable, oldRestore := enableSysProxy, restoreSysProxy
	enableSysProxy = func(port int) (sysproxy.Snapshot, error) {
		snap := sysproxy.Snapshot("user")
		if f.port != 0 {
			snap = "nautilus" // what a second snapshot would wrongly capture
		}
		f.port = port
		return snap, nil
	}
	restoreSysProxy = func(s sysproxy.Snapshot) error {
		if s != "user" {
			t.Errorf("restored %q, want the user's own settings", s)
		}
		f.port = 0
		f.restores++
		return nil
	}
	t.Cleanup(func() { enableSysProxy, restoreSysProxy = oldEnable, oldRestore })
	return f
}

func testDaemon(t *testing.T, port int) *Daemon {
	return &Daemon{state: &State{Selections: map[string]string{}}, opts: Options{DataDir: t.TempDir(), Log: io.Discard}, appliedPort: port}
}

func TestSysProxyLifecycle(t *testing.T) {
	os := swapSysProxy(t)
	d := testDaemon(t, 7890)
	if err := d.SetSysProxy(true); err != nil || os.port != 7890 {
		t.Fatalf("enable: %v, OS port %d", err, os.port)
	}
	// The kernel moved to another port: follow it, keep the user's snapshot.
	d.appliedPort = 7891
	d.syncSysProxy()
	if os.port != 7891 || d.state.SysProxy.Previous != "user" {
		t.Fatalf("after port change: OS %d, snapshot %q", os.port, d.state.SysProxy.Previous)
	}
	// Stopping restores the user's settings but keeps the wish.
	d.releaseSysProxy()
	if os.port != 0 || !d.state.SysProxy.Wanted || d.state.SysProxy.Applied {
		t.Fatalf("after stop: OS %d, state %+v", os.port, d.state.SysProxy)
	}
	// The next start turns it back on.
	d.syncSysProxy()
	if os.port != 7891 {
		t.Fatalf("after restart: OS %d", os.port)
	}
	if err := d.SetSysProxy(false); err != nil || os.port != 0 || d.state.SysProxy.Wanted {
		t.Fatalf("disable: %v, OS %d, state %+v", err, os.port, d.state.SysProxy)
	}
}

func TestRepairAfterCrash(t *testing.T) {
	os := swapSysProxy(t)
	d := testDaemon(t, 7890)
	d.SetSysProxy(true)
	// The daemon died without restoring; doctor --fix repairs it.
	repaired, err := RepairSysProxy(d.opts.DataDir)
	if err != nil || !repaired || os.port != 0 {
		t.Fatalf("repair: %v %v, OS %d", repaired, err, os.port)
	}
	if again, _ := RepairSysProxy(d.opts.DataDir); again {
		t.Error("repairing twice should find nothing to do")
	}
}

func TestSysProxyNeedsKernel(t *testing.T) {
	swapSysProxy(t)
	if err := testDaemon(t, 0).SetSysProxy(true); err == nil {
		t.Error("turning the system proxy on without a running kernel must fail")
	}
}
