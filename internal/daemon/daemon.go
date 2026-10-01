// Package daemon keeps a kernel running with the compiled profile and
// applies changes from the profile, the UI and subscriptions.
package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"nautilus/internal/auth"
	"nautilus/internal/backend"
	"nautilus/internal/backend/mihomo"
	"nautilus/internal/backend/singbox"
	"nautilus/internal/backend/xray"
	"nautilus/internal/compile"
	"nautilus/internal/control"
	"nautilus/internal/diag"
	"nautilus/internal/kernel"
	"nautilus/internal/kernels"
	"nautilus/internal/lists"
	"nautilus/internal/model"
	"nautilus/internal/route"
	"nautilus/internal/subscription"
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
	// per-user settings then: `nautilus agent` sets the system proxy in
	// each desktop session instead.
	Service bool
}

// Daemon owns one kernel process.
type Daemon struct {
	opts    Options
	Events  Bus
	sup     *kernel.Supervisor
	ctl     control.Kernel
	backend backend.Router
	bin     string
	home    string
	socket  string

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
		opts:    opts,
		backend: b,
		state:   st,
		sup:     kernel.NewSupervisor(),
		home:    filepath.Join(opts.DataDir, "home", name),
		lists:   &lists.Store{Dir: filepath.Join(opts.DataDir, "lists"), Offline: opts.Offline, Log: opts.Log},
		subs:    &subscription.Store{Dir: filepath.Join(opts.DataDir, "subscriptions"), Offline: opts.Offline, Log: opts.Log},
		subInfo: map[string]*subscription.Info{},
	}
	// The kernel API is unauthenticated on this socket: keep it in a
	// directory only this user can enter.
	runDir := filepath.Join(opts.DataDir, "run")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return nil, err
	}
	os.Chmod(runDir, 0o700)
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
	d.mu.Unlock()
	d.sup.Stop()
	d.stopSidecars()
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
	selections := d.state.Selections
	mode, tun := d.state.Mode, d.state.TUN
	d.mu.Unlock()

	merged, err := model.Load(d.opts.ProfilePath) // a copy to merge into
	if err != nil {
		return nil, nil, nil, err
	}
	mergeEntries(merged, m, temp, d.managedPath())

	var diags diag.List
	snaps := map[string]*subscription.Snapshot{}
	for _, sub := range merged.Subscriptions {
		snap, info, err := d.subs.Load(ctx, sub)
		if err != nil {
			diags.Errorf(sub.Pos, "%v", err)
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
	res.Select(selections)
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

// mergeEntries adds daemon-owned nodes, chains and routes to the profile.
// Temporary routes override other routes for the same target while they last.
func mergeEntries(p *model.Profile, m *managed, temp []TempRoute, managedPath string) {
	p.Nodes = append(p.Nodes, m.Nodes...)
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
		add(t.Key, t.Via, diag.Pos{File: "临时条目，到 " + t.Expires.Local().Format("15:04")})
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

	restarted := !running
	if running {
		err := d.ctl.Reload(ctx, art.Config, oldPort != res.Settings.MixedPort)
		if errors.Is(err, control.ErrRestart) {
			restarted = true
		} else if err != nil {
			return fmt.Errorf("重载内核配置：%w", err)
		}
	}
	if restarted {
		if err := d.sup.Start(d.ctl.Spec(d.bin, d.home, final)); err != nil {
			return err
		}
		if err := d.waitReady(ctx, res.Settings.MixedPort); err != nil {
			return err
		}
		d.startTraffic()
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
