// Package agent sets the system proxy in a desktop session for a daemon
// that runs as a system service: the proxy setting belongs to each user,
// and a service running as root or SYSTEM cannot change it.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/xiongnemo/conch/internal/api"
	"github.com/xiongnemo/conch/internal/daemon"
	"github.com/xiongnemo/conch/internal/platform/sysproxy"
)

// Events is the part of the API client the agent uses.
type Events interface {
	Events(ctx context.Context) (<-chan api.Event, error)
}

// Agent follows the daemon's wish for the system proxy.
type Agent struct {
	Client Events
	// StatePath remembers the user's own settings while the proxy points
	// at conch, so they come back even after a crash.
	StatePath string
	Log       io.Writer
	Retry     time.Duration // between attempts to reach the daemon

	// The OS setting is swapped for tests.
	Enable  func(port int) (sysproxy.Snapshot, error)
	Restore func(sysproxy.Snapshot) error

	st state
}

type state struct {
	Applied  bool   `json:"applied"`
	Port     int    `json:"port,omitempty"`
	Previous string `json:"previous,omitempty"`
}

// Run follows the daemon until ctx is done, then puts the user's
// settings back. While the daemon cannot be reached the settings are
// put back too, so the desktop never points at a proxy that is gone.
func (a *Agent) Run(ctx context.Context) error {
	if a.Enable == nil {
		a.Enable, a.Restore = sysproxy.Enable, sysproxy.Restore
	}
	if a.Retry == 0 {
		a.Retry = 3 * time.Second
	}
	a.load()
	defer a.release()
	reported := ""
	for ctx.Err() == nil {
		ch, err := a.Client.Events(ctx)
		if err != nil {
			a.release()
			if msg := err.Error(); msg != reported {
				fmt.Fprintln(a.log(), "连不上 daemon，稍后重试：", msg)
				reported = msg
			}
		} else {
			reported = ""
			a.listen(ctx, ch)
			a.release()
		}
		select {
		case <-ctx.Done():
		case <-time.After(a.Retry):
		}
	}
	return nil
}

// listen follows the daemon's states until the stream or ctx ends.
func (a *Agent) listen(ctx context.Context, ch <-chan api.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			var s daemon.Status
			if ev.Type == "state" && json.Unmarshal(ev.Data, &s) == nil {
				a.follow(s)
			}
		}
	}
}

// follow applies what a status says. A daemon that is not a service sets
// the system proxy itself; the agent leaves it alone then.
func (a *Agent) follow(s daemon.Status) {
	want := s.Service && s.SysProxy && s.Ready && s.MixedPort != 0
	if !want {
		a.release()
		return
	}
	if a.st.Applied && a.st.Port == s.MixedPort {
		return
	}
	snap, err := a.Enable(s.MixedPort)
	if err != nil {
		fmt.Fprintln(a.log(), "设置系统代理失败：", err)
		return
	}
	if !a.st.Applied {
		// Only the first snapshot is the user's own setting.
		a.st.Previous = string(snap)
	}
	a.st.Applied, a.st.Port = true, s.MixedPort
	a.save()
	fmt.Fprintf(a.log(), "系统代理已指向 127.0.0.1:%d\n", s.MixedPort)
}

func (a *Agent) release() {
	if !a.st.Applied {
		return
	}
	if err := a.Restore(sysproxy.Snapshot(a.st.Previous)); err != nil {
		fmt.Fprintln(a.log(), "恢复系统代理失败：", err)
		return
	}
	a.st = state{}
	a.save()
	fmt.Fprintln(a.log(), "已恢复原来的系统代理设置")
}

func (a *Agent) log() io.Writer {
	if a.Log == nil {
		return io.Discard
	}
	return a.Log
}

func (a *Agent) load() {
	data, err := os.ReadFile(a.StatePath)
	if err == nil {
		json.Unmarshal(data, &a.st)
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(a.log(), "读取", a.StatePath, "：", err)
	}
}

func (a *Agent) save() {
	data, _ := json.Marshal(a.st)
	os.MkdirAll(filepath.Dir(a.StatePath), 0o700)
	if err := os.WriteFile(a.StatePath, data, 0o600); err != nil {
		fmt.Fprintln(a.log(), "保存", a.StatePath, "：", err)
	}
}
