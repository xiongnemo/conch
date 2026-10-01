package daemon

import (
	"fmt"
	"net/netip"
	"net/url"
	"path/filepath"

	"nautilus/internal/platform/sysdns"
)

// The system resolver setting is swapped for tests.
var (
	dnsNeeded  = sysdns.Needed
	enableDNS  = sysdns.Enable
	restoreDNS = sysdns.Restore
)

// takeoverDNS is where the system resolver is pointed while TUN runs.
// Any address routed into TUN is captured; a public resolver keeps names
// resolving even if nautilus dies before putting the settings back.
func (d *Daemon) takeoverDNS() string {
	if d.res != nil {
		for _, ns := range d.res.Settings.DNS.Nameservers {
			host := ns
			if u, err := url.Parse(ns); err == nil && u.Host != "" {
				host = u.Hostname()
			}
			if ip, err := netip.ParseAddr(host); err == nil && ip.Is4() && !ip.IsPrivate() && !ip.IsLoopback() {
				return ip.String()
			}
		}
	}
	return "223.5.5.5"
}

// syncDNS redirects the system resolver while the applied config uses
// TUN, where the OS needs it, and restores it otherwise.
func (d *Daemon) syncDNS() {
	if !dnsNeeded() {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tun := d.applied != nil && d.res != nil && d.res.Settings.TUN.Enable
	st := d.state.DNS
	var err error
	switch {
	case tun && (st == nil || !st.Applied):
		var snap sysdns.Snapshot
		if snap, err = enableDNS(d.takeoverDNS()); err == nil {
			d.state.DNS = &DNSState{Applied: true, Previous: string(snap)}
		}
	case !tun && st != nil && st.Applied:
		if err = restoreDNS(sysdns.Snapshot(st.Previous)); err == nil {
			d.state.DNS = nil
		}
	default:
		return
	}
	if err != nil {
		fmt.Fprintln(d.opts.Log, "设置系统 DNS 失败：", err)
	}
	d.state.save(d.statePath())
}

// releaseDNS puts the system resolver back when the daemon stops.
func (d *Daemon) releaseDNS() {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := d.state.DNS
	if st == nil || !st.Applied {
		return
	}
	if err := restoreDNS(sysdns.Snapshot(st.Previous)); err != nil {
		fmt.Fprintln(d.opts.Log, "恢复系统 DNS 失败：", err)
		return
	}
	d.state.DNS = nil
	d.state.save(d.statePath())
}

// RepairDNS restores a system resolver left redirected by a daemon that
// is no longer running. It is for `nautilus doctor --fix`.
func RepairDNS(dataDir string) (bool, error) {
	path := filepath.Join(dataDir, "state.json")
	st, err := loadState(path)
	if err != nil || st.DNS == nil || !st.DNS.Applied {
		return false, err
	}
	if err := restoreDNS(sysdns.Snapshot(st.DNS.Previous)); err != nil {
		return false, err
	}
	st.DNS = nil
	return true, st.save(path)
}

// DNSLeftover reports whether a stopped daemon left the resolver redirected.
func DNSLeftover(dataDir string) bool {
	st, err := loadState(filepath.Join(dataDir, "state.json"))
	return err == nil && st.DNS != nil && st.DNS.Applied
}
