package daemon

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Run applies the profile and keeps it applied until ctx is done: it
// follows edits to profile.yaml and managed.yaml, expires temporary
// routes and refreshes subscriptions. The kernel stops when Run returns.
func (d *Daemon) Run(ctx context.Context) error {
	defer d.Stop()
	defer d.releaseSysProxy()
	defer d.releaseDNS()
	if err := d.Reconcile(ctx); err != nil {
		// Keep running: the API shows the problem and edits can fix it.
		fmt.Fprintln(d.opts.Log, "警告：", err)
	}
	d.syncSysProxy()
	changes := make(chan struct{}, 1)
	if err := d.watch(ctx, changes); err != nil {
		fmt.Fprintln(d.opts.Log, "警告：无法监听配置文件的变化：", err)
	}
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-changes:
			if err := d.Reconcile(ctx); err != nil {
				fmt.Fprintln(d.opts.Log, "配置有误，继续使用上一份可用的配置：", err)
			}
			d.syncSysProxy()
		case <-tick.C:
			d.periodic(ctx)
		}
	}
}

// periodic expires temporary routes and refreshes due subscriptions.
func (d *Daemon) periodic(ctx context.Context) {
	d.mu.Lock()
	_, expired := d.state.prune(time.Now())
	if expired {
		d.state.save(d.statePath())
	}
	p := d.profile
	d.mu.Unlock()
	changed := expired
	if p != nil && !d.opts.Offline {
		for _, sub := range p.Subscriptions {
			d.mu.Lock()
			info := d.subInfo[sub.Name]
			d.mu.Unlock()
			if info == nil || time.Since(info.FetchedAt) < interval(sub.Interval, info.UpdateInterval) {
				continue
			}
			if _, fresh, err := d.subs.Update(ctx, sub); err != nil {
				fmt.Fprintln(d.opts.Log, "更新订阅失败，继续使用缓存：", err)
			} else {
				d.mu.Lock()
				d.subInfo[sub.Name] = fresh
				d.mu.Unlock()
				changed = true
			}
		}
	}
	if changed {
		d.Reconcile(ctx)
	}
}

// interval is the subscription's refresh period: the profile's setting,
// else what the provider suggests, else a day.
func interval(setting string, providerHours int) time.Duration {
	if d, err := time.ParseDuration(setting); err == nil && d >= time.Minute {
		return d
	}
	if providerHours > 0 {
		return time.Duration(providerHours) * time.Hour
	}
	return 24 * time.Hour
}

// watch reports edits to the profile and managed.yaml. It watches the
// directory, since editors save by replacing the file, debounces bursts
// of events and ignores the daemon's own writes to managed.yaml.
func (d *Daemon) watch(ctx context.Context, changes chan<- struct{}) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	if err := w.Add(filepath.Dir(d.opts.ProfilePath)); err != nil {
		w.Close()
		return err
	}
	profile, managedFile := filepath.Clean(d.opts.ProfilePath), filepath.Clean(d.managedPath())
	go func() {
		defer w.Close()
		var debounce <-chan time.Time
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-w.Events:
				name := filepath.Clean(ev.Name)
				if name != profile && name != managedFile {
					continue
				}
				if name == managedFile {
					d.mu.Lock()
					own := fileHash(managedFile) == d.managedHash
					d.mu.Unlock()
					if own {
						continue
					}
				}
				debounce = time.After(300 * time.Millisecond)
			case <-debounce:
				select {
				case changes <- struct{}{}:
				default:
				}
			case <-w.Errors:
			}
		}
	}()
	return nil
}
