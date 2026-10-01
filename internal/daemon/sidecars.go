package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"nautilus/internal/backend"
	"nautilus/internal/compile"
	"nautilus/internal/kernel"
	"nautilus/internal/kernels"
	"nautilus/internal/sidecar"
)

// sidecarSet tracks the running sidecars and the next set to run.
type sidecarSet struct {
	mu      sync.Mutex
	running map[string]*sidecarProc // proxy name → process
	next    []sidecar.Sidecar
	bin     string
}

type sidecarProc struct {
	sup    *kernel.Supervisor
	config []byte
}

// planSidecars gives the backend a copy of res with sidecar nodes replaced
// by SOCKS5 nodes at their local ports, and remembers the sidecars to
// start once the config is applied.
func (d *Daemon) planSidecars(ctx context.Context, res *compile.Result) (*compile.Result, []backend.Forward, error) {
	needed := false
	for _, p := range res.Proxies {
		needed = needed || sidecar.Needs(p)
	}
	if !needed {
		d.sidecars.mu.Lock()
		d.sidecars.next = nil
		d.sidecars.mu.Unlock()
		return res, nil, nil
	}
	bin, err := d.sidecarBin(ctx)
	if err != nil {
		return nil, nil, err
	}
	enc, cars, forwards, err := sidecar.Plan(res, d.sidecarPorts(res))
	if err != nil {
		return nil, nil, err
	}
	d.sidecars.mu.Lock()
	d.sidecars.next, d.sidecars.bin = cars, bin
	d.sidecars.mu.Unlock()
	return enc, forwards, nil
}

// sidecarBin finds trojan-go, downloading it the first time it is needed.
func (d *Daemon) sidecarBin(ctx context.Context) (string, error) {
	if d.opts.SidecarBin != "" {
		return d.opts.SidecarBin, nil
	}
	inst, err := kernels.Current(d.opts.DataDir, sidecar.Kernel, runtime.GOOS)
	var missing *kernels.NotInstalledError
	if errors.As(err, &missing) && !d.opts.Offline {
		fmt.Fprintln(d.opts.Log, "profile 里有 trojan-go 节点，正在下载 trojan-go……")
		inst, err = kernels.Install(ctx, kernels.InstallOptions{Kernel: sidecar.Kernel, Dir: d.opts.DataDir, Target: kernels.Host(), Log: d.opts.Log})
	}
	if err != nil {
		return "", fmt.Errorf("trojan-go 节点需要 trojan-go 程序（可以运行 nautilus kernel install trojan-go）：%w", err)
	}
	return inst.Path, nil
}

// sidecarPorts returns stable local ports for every sidecar, choosing
// free ones for new sidecars.
func (d *Daemon) sidecarPorts(res *compile.Result) map[string]sidecar.Ports {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.state.Sidecars == nil {
		d.state.Sidecars = map[string]sidecar.Ports{}
	}
	ports := map[string]sidecar.Ports{}
	changed := false
	for _, p := range res.Proxies {
		if !sidecar.Needs(p) {
			continue
		}
		pp := d.state.Sidecars[p.Name]
		if pp.Local == 0 {
			pp.Local, changed = freeLocalPort(), true
		}
		if p.Upstream != "" && pp.Forward == 0 {
			pp.Forward, changed = freeLocalPort(), true
		}
		ports[p.Name] = pp
	}
	for name := range d.state.Sidecars {
		if _, ok := ports[name]; !ok {
			delete(d.state.Sidecars, name)
			changed = true
		}
	}
	if changed {
		d.state.Sidecars = ports
		d.state.save(d.statePath())
	}
	return ports
}

func freeLocalPort() int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// startSidecars brings the running sidecars in line with the applied
// config: new ones start, changed ones restart, removed ones stop.
func (d *Daemon) startSidecars() error {
	s := &d.sidecars
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running == nil {
		s.running = map[string]*sidecarProc{}
	}
	want := map[string]sidecar.Sidecar{}
	for _, c := range s.next {
		want[c.Proxy] = c
	}
	for name, proc := range s.running {
		if c, ok := want[name]; !ok || !bytes.Equal(c.Config, proc.config) {
			proc.sup.Stop()
			delete(s.running, name)
		}
	}
	dir := filepath.Join(d.home, "sidecars")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, c := range s.next {
		if _, ok := s.running[c.Proxy]; ok {
			continue
		}
		sum := sha256.Sum256([]byte(c.Proxy))
		path := filepath.Join(dir, hex.EncodeToString(sum[:6])+".json")
		if err := os.WriteFile(path, c.Config, 0o600); err != nil {
			return err
		}
		sup := kernel.NewSupervisor()
		prefix := "[trojan-go " + c.Proxy + "] "
		sup.OnLine = func(line string) bool {
			d.sup.Logs.Add(prefix + line)
			d.Events.Publish(Event{Type: "log", Data: prefix + line})
			return false
		}
		if err := sup.Start(kernel.Spec{Path: s.bin, Args: []string{"-config", path}, Dir: dir}); err != nil {
			return fmt.Errorf("启动 %q 的 trojan-go：%w", c.Proxy, err)
		}
		s.running[c.Proxy] = &sidecarProc{sup: sup, config: c.Config}
	}
	return nil
}

func (d *Daemon) stopSidecars() {
	s := &d.sidecars
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, proc := range s.running {
		proc.sup.Stop()
		delete(s.running, name)
	}
}
