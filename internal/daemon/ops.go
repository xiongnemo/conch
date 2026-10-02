package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/xiongnemo/conch/internal/compile"
	"github.com/xiongnemo/conch/internal/control"
	"github.com/xiongnemo/conch/internal/diag"
	"github.com/xiongnemo/conch/internal/explain"
	"github.com/xiongnemo/conch/internal/kernel"
	"github.com/xiongnemo/conch/internal/lists"
	"github.com/xiongnemo/conch/internal/platform/privilege"
	"github.com/xiongnemo/conch/internal/route"
	"github.com/xiongnemo/conch/internal/subscription"
)

// ErrUserFile means a change would have to edit profile.yaml, which
// conch never rewrites.
type ErrUserFile struct {
	What, Where string
}

func (e *ErrUserFile) Error() string {
	return fmt.Sprintf("%s写在 %s，conch 不会改动你手写的文件，请在那里修改", e.What, e.Where)
}

// ErrNotFound means a named thing does not exist.
var ErrNotFound = errors.New("找不到")

type Status struct {
	// Ready means a compiled profile is applied and the kernel is running.
	Ready         bool                          `json:"ready"`
	Backend       string                        `json:"backend"`
	Kernel        kernel.Status                 `json:"kernel"`
	Mode          string                        `json:"mode"`
	MixedPort     int                           `json:"mixedPort"`
	Profile       string                        `json:"profile"`
	Error         string                        `json:"error,omitempty"`
	Diagnostics   []string                      `json:"diagnostics,omitempty"`
	Subscriptions map[string]*subscription.Info `json:"subscriptions,omitempty"`
	SysProxy      bool                          `json:"sysproxy"` // the user wants the system proxy on
	TUN           bool                          `json:"tun"`      // the applied config captures traffic with TUN
	Service       bool                          `json:"service"`  // a system service: agents set the system proxy
	Caps          control.Caps                  `json:"caps"`
}

func (d *Daemon) Status() Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.statusLocked()
}

func (d *Daemon) statusLocked() Status {
	s := Status{Service: d.opts.Service, Backend: d.backend.Name(), Kernel: d.sup.Status(), Profile: d.opts.ProfilePath, Error: d.lastErr, Caps: d.ctl.Caps()}
	// A copy: callers read it after the lock is released, while
	// subscription updates write to the daemon's own.
	for name, info := range d.subInfo {
		if s.Subscriptions == nil {
			s.Subscriptions = map[string]*subscription.Info{}
		}
		c := *info
		s.Subscriptions[name] = &c
	}
	if d.res != nil {
		s.Mode, s.MixedPort = d.res.Settings.Mode, d.res.Settings.MixedPort
	}
	if d.applied != nil && d.res != nil {
		s.TUN = d.res.Settings.TUN.Enable
	}
	s.Ready = d.applied != nil && s.Kernel.State == kernel.Running
	s.SysProxy = d.state.SysProxy != nil && d.state.SysProxy.Wanted
	for _, x := range d.diags {
		s.Diagnostics = append(s.Diagnostics, x.String())
	}
	return s
}

// Logs returns recent kernel output.
func (d *Daemon) Logs() []string { return d.sup.Logs.Lines() }

// Outbound describes something traffic can be sent to.
type Outbound struct {
	Name     string   `json:"name"`
	Kind     string   `json:"kind"`           // builtin | node | group | chain
	Type     string   `json:"type,omitempty"` // protocol, or group type
	Members  []string `json:"members,omitempty"`
	Selected string   `json:"selected,omitempty"`
	Now      string   `json:"now,omitempty"` // the member a group uses right now, where known
	Hops     []string `json:"hops,omitempty"`
	Server   string   `json:"server,omitempty"`
	UDP      bool     `json:"udp,omitempty"`     // UDP traffic gets through (nodes and chains)
	Source   string   `json:"source,omitempty"`  // file:line it is written at
	Managed  bool     `json:"managed,omitempty"` // added from the UIs; they can remove it
}

// Outbounds lists the outbounds with the members groups use right now.
func (d *Daemon) Outbounds(ctx context.Context) []Outbound {
	out := d.outbounds()
	d.mu.Lock()
	art := d.art
	d.mu.Unlock()
	if art == nil {
		return out
	}
	groups := map[string]string{}
	for _, o := range out {
		if o.Kind == "group" {
			groups[d.tag(o.Name)] = o.Type
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	picks, _ := d.ctl.Picks(ctx, groups)
	names := kernelNames(art)
	for i, o := range out {
		if pick, ok := picks[d.tag(o.Name)]; ok {
			out[i].Now = names(pick)
		} else if o.Kind == "group" {
			out[i].Now = o.Selected
		}
	}
	return out
}

func (d *Daemon) outbounds() []Outbound {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := []Outbound{{Name: "DIRECT", Kind: "builtin", UDP: true}, {Name: "REJECT", Kind: "builtin"}}
	if d.res == nil {
		return out
	}
	managedFile := d.managedPath()
	at := func(o Outbound, pos diag.Pos) Outbound {
		o.Source, o.Managed = pos.String(), pos.File == managedFile
		return o
	}
	for _, g := range d.res.Groups {
		if g.Chain != "" {
			continue // a copy carrying a chain hop
		}
		o := Outbound{Name: g.Name, Kind: "group", Type: g.Type, Members: g.Members}
		if g.Type == "select" {
			o.Selected = cmpOr(d.state.Selections[g.Name], g.Selected, first(g.Members))
		}
		out = append(out, at(o, g.Pos))
	}
	for _, c := range d.res.Chains {
		out = append(out, at(Outbound{Name: c.Name, Kind: "chain", Hops: c.Path, UDP: d.res.RelaysUDP(c.Name)}, c.Pos))
	}
	for _, p := range d.res.Proxies {
		if p.Kind == compile.ProxyNode {
			out = append(out, at(Outbound{Name: p.Name, Kind: "node", Type: p.Node.View.Type,
				Server: net.JoinHostPort(p.Node.View.Server, fmt.Sprint(p.Node.View.Port)), UDP: d.res.RelaysUDP(p.Name)}, p.Node.Pos))
		}
	}
	return out
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

func (d *Daemon) group(name string) (*compile.Group, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.res != nil {
		for _, g := range d.res.Groups {
			if g.Name == name {
				return g, nil
			}
		}
	}
	return nil, fmt.Errorf("出口组 %q %w", name, ErrNotFound)
}

// Select chooses a member of a select group. It takes effect at once and
// is remembered across restarts.
func (d *Daemon) Select(ctx context.Context, groupName, member string) error {
	g, err := d.group(groupName)
	if err != nil {
		return err
	}
	if g.Type != "select" {
		return fmt.Errorf("出口组 %q 是%s，不能手动选择", groupName, groupType(g.Type))
	}
	if g.Follows != "" {
		return fmt.Errorf("%q 是链 %s 里 %s 的副本，会跟着 %s 的选择走", groupName, g.Chain, g.Follows, g.Follows)
	}
	if !slices.Contains(g.Members, member) {
		return fmt.Errorf("%q 不是出口组 %q 的成员", member, groupName)
	}
	if err := d.ctl.Select(ctx, groupName, d.tag(member)); err != nil {
		return err
	}
	// Copies of the group at later chain hops follow it.
	res := d.Result()
	for _, cp := range res.Groups {
		if cp.Follows == groupName && cp.Type == "select" {
			m := res.FollowingMember(cp, member)
			if err := d.ctl.Select(ctx, cp.Name, d.tag(m)); err != nil {
				return err
			}
			d.mu.Lock()
			cp.Selected = m
			d.mu.Unlock()
		}
	}
	d.mu.Lock()
	d.state.Selections[groupName] = member
	g.Selected = member
	err = d.state.save(d.statePath())
	d.mu.Unlock()
	d.Events.Publish(Event{Type: "state", Data: d.Status()})
	return err
}

func groupType(t string) string {
	return map[string]string{"url-test": "自动最快", "fallback": "故障转移", "load-balance": "负载均衡"}[t]
}

// DelayURL is where delay tests send their request.
const DelayURL = "https://www.gstatic.com/generate_204"

// Delay measures latency through an outbound, end to end for chains.
func (d *Daemon) Delay(ctx context.Context, name string) (time.Duration, error) {
	if !d.hasOutbound(name) && !d.isChainHop(name) {
		return 0, fmt.Errorf("出口 %q %w", name, ErrNotFound)
	}
	dl, err := d.delay(ctx, name)
	if err != nil && !errors.Is(err, control.ErrUnsupported) {
		return 0, fmt.Errorf("经由 %s 测速%w", name, err)
	}
	return dl, err
}

const delayTimeout = 5 * time.Second

// delay measures an outbound, with errors short enough to stand next to it.
func (d *Daemon) delay(ctx context.Context, name string) (time.Duration, error) {
	dl, err := d.ctl.Delay(ctx, d.tag(name), cmpOr(d.opts.DelayURL, DelayURL), delayTimeout)
	switch {
	case errors.Is(err, control.ErrUnsupported):
		return 0, fmt.Errorf("%s 内核暂不支持即时测速：%w", d.backend.Name(), err)
	case errors.Is(err, control.ErrTimeout) || errors.Is(err, context.DeadlineExceeded):
		return 0, fmt.Errorf("超时（%s 内没有响应）", delayTimeout)
	case err != nil:
		return 0, fmt.Errorf("失败：%w", err)
	}
	return dl, nil
}

// HopDelay is the delay through a chain up to and including one hop.
type HopDelay struct {
	Name  string `json:"name"`            // the hop as the chain lists it
	Delay int64  `json:"delay,omitempty"` // milliseconds
	Error string `json:"error,omitempty"`
}

// ChainDelay measures each prefix of a chain, so a chain that does not
// connect shows which hop breaks it.
func (d *Daemon) ChainDelay(ctx context.Context, name string) ([]HopDelay, error) {
	res := d.Result()
	var chain *compile.Chain
	if res != nil {
		for _, c := range res.Chains {
			if c.Name == name {
				chain = c
			}
		}
	}
	if chain == nil {
		return nil, fmt.Errorf("链 %q %w", name, ErrNotFound)
	}
	// The first hop is an outbound of its own; later hops are the clones
	// that dial through the hops before them, the last one being the chain.
	targets := []string{chain.Path[0]}
	for i := 1; i < len(chain.Path); i++ {
		target := ""
		for _, g := range res.Groups {
			if g.Chain == name && g.Hop == i {
				target = g.Name // a group at this hop, copied
			}
		}
		for _, p := range res.Proxies {
			if target == "" && p.Chain == name && p.Hop == i {
				target = p.Name
			}
		}
		targets = append(targets, target)
	}
	out := make([]HopDelay, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		out[i].Name = chain.Path[i]
		wg.Go(func() {
			dl, err := d.delay(ctx, t)
			if err != nil {
				out[i].Error = err.Error()
				return
			}
			out[i].Delay = max(dl.Milliseconds(), 1)
		})
	}
	wg.Wait()
	return out, nil
}

func (d *Daemon) isChainHop(name string) bool {
	res := d.Result()
	return res != nil && isHop(res, name)
}

// Explain says where traffic for target goes and why.
func (d *Daemon) Explain(ctx context.Context, q explain.Query) (*explain.Explanation, error) {
	d.mu.Lock()
	res := d.res
	d.mu.Unlock()
	if res == nil {
		return nil, errors.New("配置还没有成功编译")
	}
	e := &explain.Explainer{
		Result: res,
		Kernel: d.backend.Name(),
		Lists: func(p route.Provider) ([]lists.Entry, error) {
			entries, _, err := d.lists.Load(ctx, p)
			return entries, err
		},
		Resolve: func(host string) ([]netip.Addr, error) { return d.resolve(ctx, host) },
	}
	return e.Explain(q), nil
}

// resolve looks a name up the way the kernel's rules do: with its DNS when
// it can tell, which also sees past the fake addresses the system's DNS
// returns under TUN; else with the system's resolver.
func (d *Daemon) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if r, ok := d.ctl.(control.Resolver); ok && d.sup.Status().State == kernel.Running {
		kctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		addrs, err := r.Resolve(kctx, host)
		cancel()
		var dnsErr *net.DNSError
		if err == nil || errors.As(err, &dnsErr) {
			return addrs, err
		}
	}
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// ForRun is the ttl of a temporary route that lasts until conch stops.
const ForRun time.Duration = -1

// SetRoute routes key via an outbound: for ttl (or ForRun) as a temporary
// route, or, with ttl 0, for good in managed.yaml, where it also replaces
// a temporary route for key. It returns an id UndoRoute takes to put back
// what the change replaced.
func (d *Daemon) SetRoute(ctx context.Context, key, via string, ttl time.Duration) (string, error) {
	if _, _, err := route.ParseTarget(key); err != nil && key != "lan" {
		return "", err
	}
	if !d.hasOutbound(via) {
		return "", fmt.Errorf("出口 %q %w", via, ErrNotFound)
	}
	d.mu.Lock()
	p := d.profile
	u := routeUndo{key: key, setTemp: ttl != 0, temp: d.tempFor(key)}
	d.mu.Unlock()
	if ttl != 0 {
		t := TempRoute{Key: key, Via: via, Run: ttl == ForRun}
		if !t.Run {
			t.Expires = time.Now().Add(ttl).Truncate(time.Second)
		}
		if err := d.setTemp(key, &t); err != nil {
			return "", err
		}
		return d.remember(u), d.Reconcile(ctx)
	}
	if p != nil {
		if pos, ok := definedIn(p, key); ok {
			return "", &ErrUserFile{What: fmt.Sprintf("条目 %q ", key), Where: pos.String()}
		}
	}
	if m, err := loadManaged(d.managedPath()); err == nil {
		if prev, ok := m.get(key); ok {
			u.managed = &prev
		}
	}
	// The latest word wins: a temporary route for key would hide this one.
	if err := d.setTemp(key, nil); err != nil {
		return "", err
	}
	err := d.changeManaged(ctx, func(m *managed) error {
		m.set(key, via)
		return nil
	})
	if err != nil {
		d.setTemp(key, u.temp)
		return "", err
	}
	return d.remember(u), nil
}

// routeUndo is what a SetRoute replaced.
type routeUndo struct {
	id      string
	key     string
	setTemp bool       // the change was a temporary route
	temp    *TempRoute // the temporary route it replaced
	managed *string    // the managed.yaml route it replaced (permanent changes)
}

func (d *Daemon) tempFor(key string) *TempRoute {
	for _, t := range d.state.Temp {
		if sameTarget(t.Key, key) {
			return &t
		}
	}
	return nil
}

// setTemp replaces key's temporary route with t, or removes it (nil).
func (d *Daemon) setTemp(key string, t *TempRoute) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.state.Temp = slices.DeleteFunc(d.state.Temp, func(t TempRoute) bool { return sameTarget(t.Key, key) })
	if t != nil && (t.Run || t.Expires.After(time.Now())) {
		d.state.Temp = append(d.state.Temp, *t)
	}
	return d.state.save(d.statePath())
}

func (d *Daemon) remember(u routeUndo) string {
	b := make([]byte, 8)
	rand.Read(b)
	u.id = hex.EncodeToString(b)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.undos = append(d.undos, u)
	if len(d.undos) > 32 {
		d.undos = d.undos[len(d.undos)-32:]
	}
	return u.id
}

// UndoRoute puts back what the SetRoute that returned id replaced: the
// temporary route, the managed.yaml route, or nothing.
func (d *Daemon) UndoRoute(ctx context.Context, id string) error {
	d.mu.Lock()
	i := slices.IndexFunc(d.undos, func(u routeUndo) bool { return u.id == id })
	var u routeUndo
	if i >= 0 {
		u = d.undos[i]
		d.undos = slices.Delete(d.undos, i, i+1)
	}
	d.mu.Unlock()
	if i < 0 {
		return fmt.Errorf("这次修改已经不能撤销了")
	}
	if err := d.setTemp(u.key, u.temp); err != nil {
		return err
	}
	if u.setTemp {
		return d.Reconcile(ctx)
	}
	return d.changeManaged(ctx, func(m *managed) error {
		if u.managed != nil {
			m.set(u.key, *u.managed)
		} else {
			m.remove(u.key)
		}
		return nil
	})
}

// DeleteRoute removes the route for key that is in effect: a temporary
// one if there is one, which brings back the one it hid, else the one in
// managed.yaml.
func (d *Daemon) DeleteRoute(ctx context.Context, key string) error {
	d.mu.Lock()
	temp, p := d.tempFor(key), d.profile
	d.mu.Unlock()
	if temp != nil {
		if err := d.setTemp(key, nil); err != nil {
			return err
		}
		return d.Reconcile(ctx)
	}
	removed := false
	if err := d.editManaged(func(m *managed) { removed = m.remove(key) }); err != nil {
		return err
	}
	if !removed {
		if p != nil {
			if pos, ok := definedIn(p, key); ok {
				return &ErrUserFile{What: fmt.Sprintf("条目 %q ", key), Where: pos.String()}
			}
		}
		return fmt.Errorf("条目 %q %w", key, ErrNotFound)
	}
	return d.Reconcile(ctx)
}

func (d *Daemon) editManaged(edit func(*managed)) error {
	path := d.managedPath()
	m, err := loadManaged(path)
	if err != nil {
		return err
	}
	edit(m)
	if err := m.save(path); err != nil {
		return err
	}
	d.mu.Lock()
	d.managedHash = fileHash(path) // our own write; the watcher ignores it
	d.mu.Unlock()
	return nil
}

func (d *Daemon) hasOutbound(name string) bool {
	return slices.ContainsFunc(d.outbounds(), func(o Outbound) bool { return o.Name == name })
}

// SetMode switches between rule, global and direct.
func (d *Daemon) SetMode(ctx context.Context, mode string) error {
	if !slices.Contains([]string{"rule", "global", "direct"}, mode) {
		return fmt.Errorf("模式应该是 rule、global 或 direct")
	}
	d.mu.Lock()
	d.state.Mode = mode
	err := d.state.save(d.statePath())
	d.mu.Unlock()
	if err != nil {
		return err
	}
	return d.Reconcile(ctx)
}

// SetTUN turns TUN on or off, overriding the profile. If the kernel
// cannot run with it, the previous setting is kept.
func (d *Daemon) SetTUN(ctx context.Context, on bool) error {
	if on {
		if !d.backend.Capabilities().TUN {
			return fmt.Errorf("%s 内核在这个系统上暂不支持 TUN，可以换用 mihomo 或 sing-box 内核", d.backend.Name())
		}
		if err := privilege.TUNError(d.bin); err != nil {
			return err
		}
		if d.backend.Name() == "xray" {
			if err := privilege.RoutesError(); err != nil {
				return err
			}
		}
	}
	d.mu.Lock()
	old := d.state.TUN
	d.state.TUN = &on
	err := d.state.save(d.statePath())
	d.mu.Unlock()
	if err != nil {
		return err
	}
	if err := d.Reconcile(ctx); err != nil {
		d.mu.Lock()
		d.state.TUN = old
		d.state.save(d.statePath())
		d.mu.Unlock()
		return err
	}
	return nil
}

// UpdateSubscription downloads a subscription now.
func (d *Daemon) UpdateSubscription(ctx context.Context, name string) error {
	d.mu.Lock()
	p := d.profile
	d.mu.Unlock()
	if p == nil {
		return errors.New("配置还没有加载")
	}
	for _, s := range p.Subscriptions {
		if s.Name == name {
			_, info, err := d.subs.Update(ctx, s)
			if err != nil {
				return err
			}
			d.mu.Lock()
			d.subInfo[name] = info
			delete(d.subRetry, name)
			d.mu.Unlock()
			return d.Reconcile(ctx)
		}
	}
	return fmt.Errorf("订阅 %q %w", name, ErrNotFound)
}

// Restart restarts the kernel with the current config.
func (d *Daemon) Restart(ctx context.Context) error {
	d.mu.Lock()
	d.applied = nil
	d.mu.Unlock()
	d.sup.Stop()
	return d.Reconcile(ctx)
}

// Result returns the compiled profile currently applied, or nil.
func (d *Daemon) Result() *compile.Result {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.res
}

// Compiled returns the kernel config in use and the name of its file, or
// ErrNotFound before one was applied.
func (d *Daemon) Compiled() (config []byte, file string, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.art == nil {
		return nil, "", fmt.Errorf("内核配置 %w：还没有成功生成过", ErrNotFound)
	}
	return d.art.Config, d.ctl.ConfigFile(), nil
}

// Temp returns the active temporary routes.
func (d *Daemon) Temp() []TempRoute {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.state.Temp)
}
