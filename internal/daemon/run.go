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
	d.startSession()
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
			d.periodic(ctx, changes)
		}
	}
}

// periodic expires temporary routes and, in the background, refreshes
// due subscriptions and rule lists, asking for a reconcile when they got
// new content: a slow provider must not hold the daemon.
func (d *Daemon) periodic(ctx context.Context, changes chan<- struct{}) {
	d.mu.Lock()
	_, expired := d.state.prune(time.Now())
	if expired {
		d.state.save(d.statePath())
	}
	d.mu.Unlock()
	if expired {
		d.Reconcile(ctx)
	}
	if d.opts.Offline || !d.refreshing.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer d.refreshing.Store(false)
		subs := d.refreshSubscriptions(ctx, time.Now())
		if lists := d.refreshLists(ctx, time.Now()); subs || lists {
			select {
			case changes <- struct{}{}:
			default:
			}
		}
	}()
}

// listsMaxAge is how often rule lists are downloaded again. xray and
// sing-box get them inlined in their config; mihomo downloads its own,
// and conch's copy only serves explanations.
const listsMaxAge = 24 * time.Hour

// refreshLists downloads again the rule lists in use that are a day old.
func (d *Daemon) refreshLists(ctx context.Context, now time.Time) bool {
	d.mu.Lock()
	res := d.res
	d.mu.Unlock()
	if res == nil {
		return false
	}
	return d.lists.Refresh(ctx, res.Providers, listsMaxAge, now)
}

// refreshSubscriptions updates the subscriptions that are due: on their
// interval, and those that have failed, also never downloaded ones,
// again after a minute that doubles up to half an hour.
func (d *Daemon) refreshSubscriptions(ctx context.Context, now time.Time) bool {
	d.mu.Lock()
	p := d.profile
	d.mu.Unlock()
	if p == nil {
		return false
	}
	changed := false
	for _, sub := range p.Subscriptions {
		d.mu.Lock()
		info, retry := d.subInfo[sub.Name], d.subRetry[sub.Name]
		d.mu.Unlock()
		switch {
		case !retry.next.IsZero():
			if now.Before(retry.next) {
				continue
			}
		case info == nil:
			// Never downloaded: build failed on it at the start; try now.
		case now.Sub(info.FetchedAt) < interval(sub.Interval, info.UpdateInterval):
			continue
		}
		_, fresh, err := d.subs.Update(ctx, sub)
		d.mu.Lock()
		if err != nil {
			retry.wait = min(max(2*retry.wait, time.Minute), 30*time.Minute)
			retry.next = now.Add(retry.wait)
			d.subRetry[sub.Name] = retry
			d.mu.Unlock()
			fmt.Fprintf(d.opts.Log, "更新订阅失败，%s 后重试：%v\n", retry.wait, err)
			continue
		}
		delete(d.subRetry, sub.Name)
		d.subInfo[sub.Name] = fresh
		d.mu.Unlock()
		changed = true
	}
	return changed
}

// subRetry is when a subscription that failed is tried next.
type subRetry struct {
	next time.Time
	wait time.Duration
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
