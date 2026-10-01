package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	"nautilus/internal/compile"
	"nautilus/internal/control"
	"nautilus/internal/explain"
	"nautilus/internal/kernel"
	"nautilus/internal/lists"
	"nautilus/internal/route"
	"nautilus/internal/subscription"
)

// ErrUserFile means a change would have to edit profile.yaml, which
// nautilus never rewrites.
type ErrUserFile struct {
	What, Where string
}

func (e *ErrUserFile) Error() string {
	return fmt.Sprintf("%s写在 %s，nautilus 不会改动你手写的文件，请在那里修改", e.What, e.Where)
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
}

func (d *Daemon) Status() Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	s := Status{Backend: d.backend.Name(), Kernel: d.sup.Status(), Profile: d.opts.ProfilePath, Error: d.lastErr, Subscriptions: d.subInfo}
	if d.res != nil {
		s.Mode, s.MixedPort = d.res.Settings.Mode, d.res.Settings.MixedPort
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
	Hops     []string `json:"hops,omitempty"`
	Server   string   `json:"server,omitempty"`
}

func (d *Daemon) Outbounds() []Outbound {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := []Outbound{{Name: "DIRECT", Kind: "builtin"}, {Name: "REJECT", Kind: "builtin"}}
	if d.res == nil {
		return out
	}
	for _, g := range d.res.Groups {
		o := Outbound{Name: g.Name, Kind: "group", Type: g.Type, Members: g.Members}
		if g.Type == "select" {
			o.Selected = cmpOr(d.state.Selections[g.Name], g.Selected, first(g.Members))
		}
		out = append(out, o)
	}
	for _, c := range d.res.Chains {
		out = append(out, Outbound{Name: c.Name, Kind: "chain", Hops: c.Path})
	}
	for _, p := range d.res.Proxies {
		if p.Kind == compile.ProxyNode {
			out = append(out, Outbound{Name: p.Name, Kind: "node", Type: p.Node.View.Type,
				Server: net.JoinHostPort(p.Node.View.Server, fmt.Sprint(p.Node.View.Port))})
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
	if !slices.Contains(g.Members, member) {
		return fmt.Errorf("%q 不是出口组 %q 的成员", member, groupName)
	}
	if err := d.ctl.Select(ctx, groupName, d.tag(member)); err != nil {
		return err
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

// Delay measures latency through an outbound, end to end for chains.
func (d *Daemon) Delay(ctx context.Context, name string) (time.Duration, error) {
	dl, err := d.ctl.Delay(ctx, d.tag(name), "https://www.gstatic.com/generate_204", 5*time.Second)
	if errors.Is(err, control.ErrUnsupported) {
		return 0, fmt.Errorf("%s 内核暂不支持即时测速", d.backend.Name())
	}
	return dl, err
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
		Xray:   d.backend.Name() == "xray",
		Lists: func(p route.Provider) ([]lists.Entry, error) {
			entries, _, err := d.lists.Load(ctx, p)
			return entries, err
		},
		Resolve: func(host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
	}
	return e.Explain(q), nil
}

// SetRoute sends a target somewhere. With ttl > 0 the route is temporary
// and overrides other routes for the target until it expires.
func (d *Daemon) SetRoute(ctx context.Context, key, via string, ttl time.Duration) error {
	if _, _, err := route.ParseTarget(key); err != nil && key != "lan" {
		return err
	}
	if !d.hasOutbound(via) {
		return fmt.Errorf("出口 %q %w", via, ErrNotFound)
	}
	d.mu.Lock()
	p := d.profile
	d.mu.Unlock()
	if ttl > 0 {
		d.mu.Lock()
		d.state.Temp = slices.DeleteFunc(d.state.Temp, func(t TempRoute) bool { return sameTarget(t.Key, key) })
		d.state.Temp = append(d.state.Temp, TempRoute{Key: key, Via: via, Expires: time.Now().Add(ttl).Truncate(time.Second)})
		err := d.state.save(d.statePath())
		d.mu.Unlock()
		if err != nil {
			return err
		}
		return d.Reconcile(ctx)
	}
	if p != nil {
		if pos, ok := definedIn(p, key); ok {
			return &ErrUserFile{What: fmt.Sprintf("条目 %q ", key), Where: pos.String()}
		}
	}
	if err := d.editManaged(func(m *managed) { m.set(key, via) }); err != nil {
		return err
	}
	return d.Reconcile(ctx)
}

// DeleteRoute removes a temporary or daemon-managed route.
func (d *Daemon) DeleteRoute(ctx context.Context, key string) error {
	d.mu.Lock()
	n := len(d.state.Temp)
	d.state.Temp = slices.DeleteFunc(d.state.Temp, func(t TempRoute) bool { return sameTarget(t.Key, key) })
	removedTemp := len(d.state.Temp) != n
	if removedTemp {
		d.state.save(d.statePath())
	}
	p := d.profile
	d.mu.Unlock()
	removed := false
	if err := d.editManaged(func(m *managed) { removed = m.remove(key) }); err != nil {
		return err
	}
	if !removed && !removedTemp {
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
	return slices.ContainsFunc(d.Outbounds(), func(o Outbound) bool { return o.Name == name })
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

// Temp returns the active temporary routes.
func (d *Daemon) Temp() []TempRoute {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.state.Temp)
}
