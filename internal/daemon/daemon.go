// Package daemon keeps a kernel running with the compiled profile and
// applies changes from the profile, the UI and subscriptions.
package daemon

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xiongnemo/conch/internal/auth"
	"github.com/xiongnemo/conch/internal/backend"
	"github.com/xiongnemo/conch/internal/backend/mihomo"
	"github.com/xiongnemo/conch/internal/backend/singbox"
	"github.com/xiongnemo/conch/internal/backend/xray"
	"github.com/xiongnemo/conch/internal/compile"
	"github.com/xiongnemo/conch/internal/control"
	"github.com/xiongnemo/conch/internal/diag"
	"github.com/xiongnemo/conch/internal/kernel"
	"github.com/xiongnemo/conch/internal/kernels"
	"github.com/xiongnemo/conch/internal/lists"
	"github.com/xiongnemo/conch/internal/model"
	"github.com/xiongnemo/conch/internal/platform/firewall"
	"github.com/xiongnemo/conch/internal/platform/privilege"
	"github.com/xiongnemo/conch/internal/platform/tunroute"
	"github.com/xiongnemo/conch/internal/route"
	"github.com/xiongnemo/conch/internal/subscription"
)

// Options configure a daemon.
type Options struct {
	ProfilePath string
	DataDir     string
	Backend     string // mihomo | xray; empty keeps the last one used
	KernelBin   string // empty means the installed kernel
	SidecarBin  string // trojan-go; empty means the installed one
	Offline     bool   // never download subscriptions or rule lists
	Log         io.Writer
	DelayURL    string // what delay tests request; empty means DelayURL
	// Service means the daemon runs as a system service. It cannot change
	// per-user settings then: `conch agent` sets the system proxy in
	// each desktop session instead.
	Service bool
}

// Daemon owns one kernel process.
type Daemon struct {
	opts   Options
	Events Bus
	sup    *kernel.Supervisor
	ctl    control.Kernel
	// the kernel binary let through Windows' firewall, for TUN
	firewalled string
	// the system is routed into xray's TUN device
	tunRouted bool
	// inbound.system-proxy as last applied, to notice the profile changing it
	profileSysProxy *bool
	lanOpen         bool                // the proxy listens beyond loopback (noteLAN)
	undos           []routeUndo         // the latest route changes, for UndoRoute
	refreshing      atomic.Bool         // subscriptions are being refreshed
	geodataTried    time.Time           // xray's geodata was last downloaded (refreshGeodata)
	subRetry        map[string]subRetry // failed subscriptions, by name
	backend         backend.Router
	bin             string
	home            string
	socket          string

	lists *lists.Store
	subs  *subscription.Store

	reconcileMu sync.Mutex // one reconcile at a time

	mu          sync.Mutex
	state       *State
	profile     *model.Profile // as loaded, before merging
	res         *compile.Result
	art         *backend.Artifact
	applied     []byte
	appliedPort int
	diags       diag.List
	lastErr     string
	subInfo     map[string]*subscription.Info
	managedHash [32]byte
	stopTraffic context.CancelFunc
	probes      []string // sockets of the kernel's delay-test inbounds
	controller  string   // the kernel API's TCP address, for kernels without unix sockets
	secret      string
	logLevel    atomic.Value // string: the profile's log-level

	failures failures

	sidecars sidecarSet
}

var backends = map[string]backend.Router{"mihomo": mihomo.Backend{}, "xray": xray.Backend{}, "sing-box": singbox.Backend{}}

func New(opts Options) (*Daemon, error) {
	if opts.Log == nil {
		opts.Log = io.Discard
	}
	st, err := loadState(filepath.Join(opts.DataDir, "state.json"))
	if err != nil {
		return nil, fmt.Errorf("读取 state.json：%w", err)
	}
	name := cmpOr(opts.Backend, st.Backend, "mihomo")
	b, ok := backends[name]
	if !ok {
		return nil, fmt.Errorf("不认识的后端 %q", name)
	}
	st.Backend = name
	d := &Daemon{
		opts:     opts,
		backend:  b,
		state:    st,
		sup:      kernel.NewSupervisor(),
		home:     filepath.Join(opts.DataDir, "home", name),
		lists:    &lists.Store{Dir: filepath.Join(opts.DataDir, "lists"), Offline: opts.Offline, Log: opts.Log},
		subs:     &subscription.Store{Dir: filepath.Join(opts.DataDir, "subscriptions"), Offline: opts.Offline, Log: opts.Log},
		subInfo:  map[string]*subscription.Info{},
		subRetry: map[string]subRetry{},
	}
	d.lists.Proxy, d.subs.Proxy = d.kernelProxy, d.kernelProxy
	// The kernel API is unauthenticated on this socket: keep it in a
	// directory only this user can enter.
	runDir := socketDir(opts.DataDir)
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return nil, err
	}
	os.Chmod(runDir, 0o700)
	// A daemon that died may have left its kernel running, on the ports
	// this one needs; also another kernel, from before a switch.
	for _, k := range []string{"mihomo", "xray", "sing-box"} {
		if kernel.KillOrphan(filepath.Join(runDir, k+".pid")) {
			fmt.Fprintf(opts.Log, "已结束上次没有退出的 %s 内核\n", k)
		}
	}
	d.socket = filepath.Join(runDir, name+".sock")
	if err := os.MkdirAll(d.home, 0o755); err != nil {
		return nil, err
	}
	d.bin = opts.KernelBin
	if d.bin == "" {
		inst, err := kernels.Current(opts.DataDir, name, kernels.Host().OS)
		if err != nil {
			return nil, err
		}
		d.bin = inst.Path
	}
	switch name {
	case "mihomo":
		d.ctl = control.NewMihomo(d.socket)
	case "xray":
		x := &control.Xray{Bin: d.bin, Socket: d.socket}
		for i := range xrayProbes {
			socket := filepath.Join(runDir, fmt.Sprintf("xray-probe-%d.sock", i+1))
			x.Probes = append(x.Probes, control.Probe{Tag: xray.ProbeTag(i), Socket: socket})
			d.probes = append(d.probes, socket)
		}
		d.ctl = x
	case "sing-box":
		// Its API only listens on TCP: a loopback port with a secret.
		d.controller, d.secret = fmt.Sprintf("127.0.0.1:%d", freeLocalPort()), auth.NewPassword()
		d.ctl = control.NewSingBox(d.controller, d.secret)
	}
	d.sup.OnRestart = func() {
		d.mu.Lock()
		routed := d.tunRouted
		d.mu.Unlock()
		if routed { // the device came back with the kernel, the routes into it did not
			if err := tunroute.Up(xray.TUNDevice); err != nil {
				fmt.Fprintln(d.opts.Log, "警告：", err)
			}
		}
	}
	d.sup.OnLine = func(l string) bool {
		ll := d.ctl.ObserveLog(l)
		if ll.Failure != nil {
			d.failures.add(*ll.Failure, time.Now())
		}
		level, _ := d.logLevel.Load().(string)
		if ll.Internal || !shown(ll.Level, level) {
			return false
		}
		d.Events.Publish(Event{Type: "log", Data: l})
		return true
	}
	return d, nil
}

// xrayProbes is how many delay tests can run at once on xray.
const xrayProbes = 4

// shown reports whether a line at level appears in the log users see,
// which follows the profile's log-level even when the kernel logs more.
func shown(level, setting string) bool {
	return level == "" || setting == "" || backend.LogLevel(setting, level) == setting
}

func cmpOr(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

func (d *Daemon) statePath() string   { return filepath.Join(d.opts.DataDir, "state.json") }
func (d *Daemon) managedPath() string { return ManagedPath(d.opts.ProfilePath) }

// Stop ends the kernel and its sidecars.
func (d *Daemon) Stop() {
	d.mu.Lock()
	if d.stopTraffic != nil {
		d.stopTraffic()
	}
	routed := d.tunRouted
	d.tunRouted = false
	d.mu.Unlock()
	d.sup.Stop()
	d.stopSidecars()
	if routed {
		tunroute.Down()
	}
}

// routeTUN routes the system into xray's TUN device when TUN is on, and
// back out when it is off: xray only brings the device up. It runs after
// every start of the kernel, whose new device starts without routes.
func (d *Daemon) routeTUN(res *compile.Result) error {
	want := d.backend.Name() == "xray" && res.Settings.TUN.Enable
	d.mu.Lock()
	routed := d.tunRouted
	d.mu.Unlock()
	switch {
	case want:
		if err := tunroute.Up(xray.TUNDevice); err != nil {
			return err
		}
	case routed:
		tunroute.Down()
	default:
		return nil
	}
	d.mu.Lock()
	d.tunRouted = want
	d.mu.Unlock()
	return nil
}

// ErrConfig wraps profile problems; the kernel keeps its last good config.
type ErrConfig struct{ Diags diag.List }

func (e *ErrConfig) Error() string { return e.Diags.Err().Error() }

// Reconcile compiles the current profile and brings the kernel in line
// with it. If the new config is invalid the kernel keeps running the last
// good one.
func (d *Daemon) Reconcile(ctx context.Context) error {
	d.reconcileMu.Lock()
	defer d.reconcileMu.Unlock()

	res, art, diags, err := d.build(ctx)
	if err == nil && art == nil {
		err = &ErrConfig{Diags: diags}
	}
	if err == nil {
		err = d.apply(ctx, res, art)
	}
	if err == nil {
		// Also when the kernel's config stays the same: the setting
		// is conch's own.
		d.followProfileSysProxy(res)
		d.noteLAN(res.Settings)
	}
	d.mu.Lock()
	d.diags = diags
	d.lastErr = ""
	if err != nil {
		d.lastErr = err.Error()
	}
	d.mu.Unlock()
	d.syncDNS()
	d.Events.Publish(Event{Type: "state", Data: d.Status()})
	return err
}

// kernelProxy is the running kernel's port, for downloads that failed
// directly; nil while no kernel runs.
func (d *Daemon) kernelProxy() *url.URL {
	if d.sup.Status().State != kernel.Running {
		return nil
	}
	d.mu.Lock()
	port := d.appliedPort
	d.mu.Unlock()
	if port == 0 {
		return nil
	}
	return &url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(port))}
}

// noteLAN says, when the proxy starts listening beyond this machine, that
// it does so without a password.
func (d *Daemon) noteLAN(s compile.Settings) {
	open := s.AllowLAN && !auth.IsLoopback(cmpOr(s.BindAddress, "*"))
	if open && !d.lanOpen {
		fmt.Fprintf(d.opts.Log, "注意：inbound.allow-lan 打开了，局域网里的设备不用密码就能使用 %d 端口的代理；只在信得过的网络里这样用\n", s.MixedPort)
	}
	d.lanOpen = open
}

// build loads everything a config depends on and compiles it.
func (d *Daemon) build(ctx context.Context) (*compile.Result, *backend.Artifact, diag.List, error) {
	p, err := model.Load(d.opts.ProfilePath)
	if err != nil {
		return nil, nil, nil, err
	}
	m, err := loadManaged(d.managedPath())
	if err != nil {
		return nil, nil, nil, err
	}
	d.mu.Lock()
	d.profile = p
	if _, changed := d.state.prune(time.Now()); changed {
		d.state.save(d.statePath())
	}
	temp := append([]TempRoute(nil), d.state.Temp...)
	selections := maps.Clone(d.state.Selections)
	mode, tun := d.state.Mode, d.state.TUN
	prev := d.res
	d.mu.Unlock()

	merged, err := model.Load(d.opts.ProfilePath) // a copy to merge into
	if err != nil {
		return nil, nil, nil, err
	}
	mergeEntries(merged, m, temp, d.managedPath())

	var diags diag.List
	snaps := map[string]*subscription.Snapshot{}
	type failed struct {
		pos diag.Pos
		err error
	}
	var missing []failed // subscriptions with nothing to go on yet
	for _, sub := range merged.Subscriptions {
		snap, info, err := d.subs.Load(ctx, sub)
		if err != nil {
			missing = append(missing, failed{sub.Pos, err})
			continue
		}
		snaps[sub.Name] = snap
		d.mu.Lock()
		d.subInfo[sub.Name] = info
		d.mu.Unlock()
	}
	subscription.Apply(merged, snaps, &diags)
	if mode != "" {
		merged.Mode = mode
	}
	if tun != nil {
		merged.TUN.Enable = *tun
	}
	res := compile.Compile(merged)
	diags = append(diags, res.Diags...)
	// A profile that works without a subscription runs without it until it
	// downloads, which can then go through the kernel; one that needs it
	// cannot run.
	var subDiags diag.List
	for _, m := range missing {
		if diags.HasErrors() {
			subDiags.Errorf(m.pos, "%v", m.err)
		} else {
			subDiags.Warnf(m.pos, "%v；先不用这个订阅，之后会自动重试", m.err)
		}
	}
	diags = append(subDiags, diags...)
	if moved := followRenames(prev, res, selections); len(moved) > 0 {
		d.mu.Lock()
		for g, m := range moved {
			fmt.Fprintf(d.opts.Log, "出口组 %s 里选中的节点 %s 改名成了 %s，继续选它\n", g, selections[g], m)
			selections[g], d.state.Selections[g] = m, m
		}
		d.state.save(d.statePath())
		d.mu.Unlock()
	}
	res.Select(selections)
	// TUN asked for in the profile gets the check the switch does: a
	// kernel that cannot create the device would fail where a check of
	// its config cannot tell (mihomo even reloads without a word).
	if res.Settings.TUN.Enable && d.backend.Capabilities().TUN {
		if err := privilege.TUNError(d.bin); err != nil {
			diags.Errorf(diag.Pos{}, "%v", err)
		} else if d.backend.Name() == "xray" {
			if err := privilege.RoutesError(); err != nil {
				diags.Errorf(diag.Pos{}, "%v", err)
			}
		}
	}
	if diags.HasErrors() {
		return res, nil, diags, nil
	}
	// Nodes the kernel cannot speak run in sidecars it reaches over SOCKS5.
	enc, forwards, err := d.planSidecars(ctx, res)
	if err != nil {
		diags.Errorf(diag.Pos{}, "%v", err)
		return res, nil, diags, nil
	}
	diags = append(diags, backend.Check(enc, d.backend.Capabilities(), d.backend.Name())...)
	if diags.HasErrors() {
		return res, nil, diags, nil
	}
	opts := backend.Options{ControllerUnix: d.socket, Lists: d.listLoader(ctx), Probes: d.probes, MinLogLevel: d.ctl.LogLevel(), Forwards: forwards}
	if d.controller != "" {
		opts.ControllerUnix, opts.Controller, opts.Secret = "", d.controller, d.secret
	}
	art, more := d.backend.Encode(enc, opts)
	diags = append(diags, more...)
	if diags.HasErrors() {
		return res, nil, diags, nil
	}
	return res, art, diags, nil
}

// followRenames finds the selections a subscription update broke by
// renaming the selected node: when a select group no longer has the
// member it had, a member that is the same node under a new name takes
// its place. It returns the new choices by group.
func followRenames(prev, res *compile.Result, selections map[string]string) map[string]string {
	if prev == nil {
		return nil
	}
	moved := map[string]string{}
	for _, g := range res.Groups {
		old, ok := selections[g.Name]
		if !ok || g.Type != "select" || g.Chain != "" || slices.Contains(g.Members, old) {
			continue
		}
		was := nodeNamed(prev, old)
		if was == nil {
			continue
		}
		for _, m := range g.Members {
			if n := nodeNamed(res, m); n != nil && n.Identity() == was.Identity() {
				moved[g.Name] = m
				break
			}
		}
	}
	return moved
}

func nodeNamed(res *compile.Result, name string) *model.Node {
	for _, p := range res.Proxies {
		if p.Name == name && p.Kind == compile.ProxyNode {
			return p.Node
		}
	}
	return nil
}

// mergeEntries adds daemon-owned nodes, groups, chains and routes to the
// profile.
// Temporary routes override other routes for the same target while they last.
func mergeEntries(p *model.Profile, m *managed, temp []TempRoute, managedPath string) {
	p.Nodes = append(p.Nodes, m.Nodes...)
	p.Groups = append(p.Groups, m.Groups...)
	p.Chains = append(p.Chains, m.Chains...)
	add := func(key, via string, pos diag.Pos) {
		p.Routes.Entries = append(p.Routes.Entries, &model.Entry{Key: key, Via: model.Via{Name: via}, Pos: pos})
	}
	drop := func(key string) {
		kept := p.Routes.Entries[:0]
		for _, e := range p.Routes.Entries {
			if !sameTarget(e.Key, key) {
				kept = append(kept, e)
			}
		}
		p.Routes.Entries = kept
	}
	for _, e := range m.Entries {
		pos := e.Pos
		if pos.File == "" {
			pos.File = managedPath
		}
		add(e.Key, e.Via, pos)
	}
	for _, t := range temp {
		drop(t.Key)
		if t.Run {
			add(t.Key, t.Via, diag.Pos{File: "临时条目，本次运行"})
		} else {
			add(t.Key, t.Via, diag.Pos{File: "临时条目，到 " + t.Expires.Local().Format("15:04")})
		}
	}
}

func (d *Daemon) listLoader(ctx context.Context) backend.ListLoader {
	return func(p route.Provider) ([]lists.Entry, []string, error) { return d.lists.Load(ctx, p) }
}

// apply validates a config and hands it to the kernel.
func (d *Daemon) apply(ctx context.Context, res *compile.Result, art *backend.Artifact) error {
	d.mu.Lock()
	same := bytes.Equal(art.Config, d.applied)
	oldPort := d.appliedPort
	d.mu.Unlock()
	running := d.sup.Status().State == kernel.Running
	if same && running {
		d.mu.Lock()
		d.res, d.art = res, art
		d.mu.Unlock()
		d.logLevel.Store(res.Settings.LogLevel)
		return d.startSidecars()
	}

	// A port someone else holds: mihomo would reload without a word and
	// listen nowhere, the others fail to start.
	if !running || oldPort != res.Settings.MixedPort {
		if err := portFree(res.Settings); err != nil {
			return err
		}
	}

	final := filepath.Join(d.home, d.ctl.ConfigFile())
	// xray picks the format from the extension, so keep it last.
	next := filepath.Join(d.home, "next."+d.ctl.ConfigFile())
	if err := os.WriteFile(next, art.Config, 0o600); err != nil {
		return err
	}
	if err := d.ctl.Validate(ctx, d.bin, d.home, next); err != nil {
		os.Remove(next)
		return err
	}
	if err := os.Rename(next, final); err != nil {
		return err
	}

	// Windows' firewall keeps TUN's system stack from reaching the kernel.
	if res.Settings.TUN.Enable && runtime.GOOS == "windows" && d.firewalled != d.bin {
		if err := firewall.Allow(d.backend.Name(), d.bin); err != nil {
			fmt.Fprintf(d.opts.Log, "警告： 没能在 Windows 防火墙里放行内核（%v），TUN 可能连不通\n", err)
		} else {
			d.firewalled = d.bin
		}
	}

	restarted := !running
	if running {
		err := d.ctl.Reload(ctx, art.Config, oldPort != res.Settings.MixedPort)
		if errors.Is(err, control.ErrRestart) {
			restarted = true
		} else if err != nil {
			d.rollback(ctx, final)
			return fmt.Errorf("重载内核配置：%w", err)
		}
	}
	if restarted {
		if err := d.start(ctx, final, res); err != nil {
			d.rollback(ctx, final)
			return err
		}
	}
	d.mu.Lock()
	d.res, d.art, d.applied, d.appliedPort = res, art, art.Config, res.Settings.MixedPort
	d.mu.Unlock()
	d.logLevel.Store(res.Settings.LogLevel)
	if err := d.startSidecars(); err != nil {
		return err
	}
	if restarted || d.backend.Name() == "mihomo" {
		d.restoreSelections(ctx, res)
	}
	return nil
}

// portFree reports a mixed port another program listens on.
func portFree(s compile.Settings) error {
	host := "127.0.0.1"
	if s.AllowLAN {
		host = cmp.Or(s.BindAddress, "0.0.0.0")
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(s.MixedPort)))
	if err != nil {
		return fmt.Errorf("代理端口 %d 已经被别的程序占用了：可以退出那个程序，或者在 profile 里改 inbound.mixed-port", s.MixedPort)
	}
	ln.Close()
	return nil
}

// start (re)starts the kernel on its config file and waits until it works.
func (d *Daemon) start(ctx context.Context, final string, res *compile.Result) error {
	spec := d.ctl.Spec(d.bin, d.home, final)
	spec.PidFile = filepath.Join(filepath.Dir(d.socket), d.backend.Name()+".pid")
	for _, s := range append([]string{d.socket}, d.probes...) {
		spec.Clean = append(spec.Clean, s, s+".lock") // xray locks its sockets
	}
	if err := d.sup.Start(spec); err != nil {
		return err
	}
	if err := d.waitReady(ctx, res.Settings.MixedPort); err != nil {
		return err
	}
	if err := d.routeTUN(res); err != nil {
		return err
	}
	d.startTraffic()
	return nil
}

// rollback puts the last config that worked back after a new one made
// the kernel fail where checking it could not tell (a port taken, TUN
// without the rights), so a bad change never leaves the user without a
// proxy. With no config that worked yet, the supervisor keeps retrying.
func (d *Daemon) rollback(ctx context.Context, final string) {
	d.mu.Lock()
	prev, res := d.applied, d.res
	d.mu.Unlock()
	if prev == nil || res == nil {
		return
	}
	fmt.Fprintln(d.opts.Log, "新配置让内核出错，已换回上一份可用的配置")
	if err := os.WriteFile(final, prev, 0o600); err != nil {
		fmt.Fprintln(d.opts.Log, "警告：", err)
		return
	}
	if err := d.ctl.Reload(ctx, prev, true); err == nil && d.sup.Status().State == kernel.Running {
		return
	}
	if err := d.start(ctx, final, res); err != nil {
		fmt.Fprintln(d.opts.Log, "警告：上一份配置也没能启动内核：", err)
	}
}

// waitReady waits until the kernel API answers and the proxy port accepts.
func (d *Daemon) waitReady(ctx context.Context, port int) error {
	deadline := time.Now().Add(60 * time.Second) // big configs on routers start slowly
	for {
		if d.ctl.Ready(ctx) {
			if c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second); err == nil {
				c.Close()
				return nil
			}
		}
		if st := d.sup.Status(); st.State != kernel.Running && st.State != kernel.Starting {
			return fmt.Errorf("内核启动失败（%s）：%s", st.LastExit, lastLog(d.sup.Logs.Lines()))
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("内核 60 秒内没有就绪：%s", lastLog(d.sup.Logs.Lines()))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func lastLog(lines []string) string {
	if len(lines) == 0 {
		return "没有输出"
	}
	return lines[len(lines)-1]
}

// restoreSelections re-applies choices made in the UI. mihomo restores
// them itself from its cache, but only by name; doing it explicitly also
// covers renamed or newly created groups.
func (d *Daemon) restoreSelections(ctx context.Context, res *compile.Result) {
	for _, g := range res.Groups {
		if g.Selected != "" {
			d.ctl.Select(ctx, g.Name, d.tag(g.Selected))
		}
	}
}

// tag maps an outbound name to the kernel's identifier for it.
func (d *Daemon) tag(name string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.art != nil {
		if t, ok := d.art.Manifest.Tags[name]; ok {
			return t
		}
	}
	return name
}

func (d *Daemon) startTraffic() {
	d.mu.Lock()
	if d.stopTraffic != nil {
		d.stopTraffic()
	}
	ctx, cancel := context.WithCancel(context.Background())
	d.stopTraffic = cancel
	d.mu.Unlock()
	go func() {
		for ctx.Err() == nil {
			ch, err := d.ctl.Traffic(ctx)
			if err == nil {
				for t := range ch {
					d.Events.Publish(Event{Type: "traffic", Data: t})
				}
			}
			select {
			case <-ctx.Done():
			case <-time.After(2 * time.Second):
			}
		}
	}()
}

func fileHash(path string) [32]byte {
	data, _ := os.ReadFile(path)
	return sha256.Sum256(data)
}

// socketDir is where the kernels' unix sockets go: in the data directory,
// unless their paths would be too long for a socket (about 100 bytes on
// every OS), as a deep data directory makes them. Then in a directory of
// the user's temporary directory named after it.
func socketDir(dataDir string) string {
	dir := filepath.Join(dataDir, "run")
	if len(filepath.Join(dir, "xray-probe-0.sock")) <= 100 {
		return dir
	}
	sum := sha256.Sum256([]byte(dataDir))
	return filepath.Join(os.TempDir(), "conch-"+hex.EncodeToString(sum[:4]))
}
