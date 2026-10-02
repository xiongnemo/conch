package daemon

import (
	"io"
	"testing"

	"github.com/xiongnemo/conch/internal/compile"

	"github.com/xiongnemo/conch/internal/platform/sysproxy"
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
			snap = "conch" // what a second snapshot would wrongly capture
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
	if err := d.SetSysProxy(false); err != nil || os.port != 0 || d.state.SysProxy.Wanted {
		t.Fatalf("disable: %v, OS %d, state %+v", err, os.port, d.state.SysProxy)
	}
	d.SetSysProxy(true)
	// Stopping restores the user's settings.
	d.releaseSysProxy()
	if os.port != 0 || d.state.SysProxy.Applied {
		t.Fatalf("after stop: OS %d, state %+v", os.port, d.state.SysProxy)
	}
	// The next start is a plain proxy again: the switch lasted one run.
	start(d, false)
	if os.port != 0 || d.state.SysProxy.Wanted {
		t.Fatalf("after restart: OS %d, state %+v", os.port, d.state.SysProxy)
	}
}

// start runs a daemon start as Run does, with inbound.system-proxy.
func start(d *Daemon, systemProxy bool) {
	d.startSession()
	d.followProfileSysProxy(&compile.Result{Settings: compile.Settings{SystemProxy: systemProxy}})
	d.syncSysProxy()
}

// inbound.system-proxy turns it on at every start, and when an edit of the
// profile asks for it; the switch in the UIs lasts until then.
func TestProfileSystemProxy(t *testing.T) {
	os := swapSysProxy(t)
	d := testDaemon(t, 7890)
	start(d, true)
	if os.port != 7890 {
		t.Fatalf("start with system-proxy: OS %d", os.port)
	}
	d.SetSysProxy(false)
	d.followProfileSysProxy(&compile.Result{Settings: compile.Settings{SystemProxy: true}}) // another edit, same value
	d.syncSysProxy()
	if os.port != 0 {
		t.Fatalf("the profile overrode the switch without changing: OS %d", os.port)
	}
	d.followProfileSysProxy(&compile.Result{Settings: compile.Settings{SystemProxy: false}})
	d.followProfileSysProxy(&compile.Result{Settings: compile.Settings{SystemProxy: true}})
	d.syncSysProxy()
	if os.port != 7890 {
		t.Fatalf("after the profile turned it on again: OS %d", os.port)
	}
}

// A TUN switch lasts one run too; tun.enable in the profile is for every start.
func TestStartResetsTUN(t *testing.T) {
	swapSysProxy(t)
	d := testDaemon(t, 7890)
	on := true
	d.state.TUN = &on
	d.startSession()
	if d.state.TUN != nil {
		t.Errorf("TUN switch survived a restart: %v", *d.state.TUN)
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
