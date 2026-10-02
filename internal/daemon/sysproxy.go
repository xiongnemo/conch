package daemon

import (
	"fmt"
	"path/filepath"

	"github.com/xiongnemo/conch/internal/platform/sysproxy"
)

// The OS proxy setting is swapped for tests.
var (
	enableSysProxy  = sysproxy.Enable
	restoreSysProxy = sysproxy.Restore
)

// SetSysProxy turns the system proxy on or off and remembers the choice.
func (d *Daemon) SetSysProxy(on bool) error {
	d.mu.Lock()
	port := d.appliedPort
	d.mu.Unlock()
	if on && port == 0 {
		return fmt.Errorf("内核还没有运行，无法设置系统代理")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.state.SysProxy == nil {
		d.state.SysProxy = &SysProxyState{}
	}
	sp := d.state.SysProxy
	sp.Wanted = on
	var err error
	switch {
	case d.opts.Service:
		// Agents in the desktop sessions follow the wish.
		d.Events.Publish(Event{Type: "state", Data: d.statusLocked()})
	case on:
		err = d.applySysProxy(port)
	default:
		err = d.unapplySysProxy()
	}
	if saveErr := d.state.save(d.statePath()); err == nil {
		err = saveErr
	}
	return err
}

// applySysProxy points the OS at port; d.mu must be held. The snapshot of
// the user's own settings is taken only once, so pointing at a new port
// never records conch' previous setting as the one to restore.
func (d *Daemon) applySysProxy(port int) error {
	sp := d.state.SysProxy
	snap, err := enableSysProxy(port)
	if err != nil {
		return err
	}
	if !sp.Applied {
		sp.Previous = string(snap)
	}
	sp.Applied, sp.Port = true, port
	return nil
}

// unapplySysProxy restores the user's settings; d.mu must be held.
func (d *Daemon) unapplySysProxy() error {
	sp := d.state.SysProxy
	if sp == nil || !sp.Applied {
		return nil
	}
	if err := restoreSysProxy(sysproxy.Snapshot(sp.Previous)); err != nil {
		return err
	}
	sp.Applied, sp.Port, sp.Previous = false, 0, ""
	return nil
}

// syncSysProxy brings the OS setting in line with the user's wish after
// the kernel (re)started: re-applied when the port changed, repaired
// after a crash, or restored when the user no longer wants it.
func (d *Daemon) syncSysProxy() {
	d.mu.Lock()
	defer d.mu.Unlock()
	sp := d.state.SysProxy
	if sp == nil || d.opts.Service {
		return
	}
	var err error
	switch {
	case sp.Wanted && (!sp.Applied || sp.Port != d.appliedPort) && d.appliedPort != 0:
		err = d.applySysProxy(d.appliedPort)
	case !sp.Wanted && sp.Applied:
		err = d.unapplySysProxy()
	default:
		return
	}
	if err != nil {
		fmt.Fprintln(d.opts.Log, "设置系统代理失败：", err)
	}
	d.state.save(d.statePath())
}

// releaseSysProxy puts the user's settings back when the daemon stops;
// the wish is kept, so the next start turns it on again.
func (d *Daemon) releaseSysProxy() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.opts.Service {
		return
	}
	if err := d.unapplySysProxy(); err != nil {
		fmt.Fprintln(d.opts.Log, "恢复系统代理失败：", err)
	}
	d.state.save(d.statePath())
}

// RepairSysProxy restores a system proxy left pointing at a daemon that is
// no longer running. It is for `conch doctor --fix`.
func RepairSysProxy(dataDir string) (bool, error) {
	path := filepath.Join(dataDir, "state.json")
	st, err := loadState(path)
	if err != nil || st.SysProxy == nil || !st.SysProxy.Applied {
		return false, err
	}
	if err := restoreSysProxy(sysproxy.Snapshot(st.SysProxy.Previous)); err != nil {
		return false, err
	}
	st.SysProxy.Applied, st.SysProxy.Port, st.SysProxy.Previous = false, 0, ""
	return true, st.save(path)
}
