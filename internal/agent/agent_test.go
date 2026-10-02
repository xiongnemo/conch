package agent

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/xiongnemo/conch/internal/api"
	"github.com/xiongnemo/conch/internal/daemon"
	"github.com/xiongnemo/conch/internal/platform/sysproxy"
)

// daemonStub hands out one event stream per connection.
type daemonStub struct {
	streams chan chan api.Event
}

func (d *daemonStub) Events(ctx context.Context) (<-chan api.Event, error) {
	select {
	case ch := <-d.streams:
		return ch, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(20 * time.Millisecond):
		return nil, errors.New("not running")
	}
}

func stateEvent(s daemon.Status) api.Event {
	data, _ := json.Marshal(s)
	return api.Event{Type: "state", Data: data}
}

type desktop struct {
	mu      sync.Mutex
	setting string // what the OS points at
	log     []string
}

func (d *desktop) enable(port int) (sysproxy.Snapshot, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	prev := d.setting
	d.setting = "127.0.0.1:" + itoa(port)
	d.log = append(d.log, "enable "+d.setting)
	return sysproxy.Snapshot(prev), nil
}

func (d *desktop) restore(s sysproxy.Snapshot) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.setting = string(s)
	d.log = append(d.log, "restore "+string(s))
	return nil
}

func (d *desktop) now() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.setting
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); !cond(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for", what)
		}
	}
}

func TestAgent(t *testing.T) {
	stub := &daemonStub{streams: make(chan chan api.Event)}
	desk := &desktop{setting: "corp-proxy:3128"}
	path := filepath.Join(t.TempDir(), "agent.json")
	a := &Agent{Client: stub, StatePath: path, Retry: 10 * time.Millisecond, Enable: desk.enable, Restore: desk.restore}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()

	service := daemon.Status{Service: true, Ready: true, MixedPort: 7890}
	stream := make(chan api.Event, 4)
	stub.streams <- stream
	stream <- stateEvent(service) // the user has not asked for the proxy
	service.SysProxy = true
	stream <- stateEvent(service)
	waitFor(t, "the proxy to be set", func() bool { return desk.now() == "127.0.0.1:7890" })
	service.MixedPort = 7891 // the profile moved the port
	stream <- stateEvent(service)
	waitFor(t, "the new port", func() bool { return desk.now() == "127.0.0.1:7891" })

	// The daemon goes away: the desktop must not point at a dead proxy.
	close(stream)
	waitFor(t, "the user's setting back", func() bool { return desk.now() == "corp-proxy:3128" })

	// A daemon that sets the proxy itself is left alone.
	stream = make(chan api.Event, 4)
	stub.streams <- stream
	stream <- stateEvent(daemon.Status{Service: false, SysProxy: true, Ready: true, MixedPort: 7890})
	time.Sleep(50 * time.Millisecond)
	if desk.now() != "corp-proxy:3128" {
		t.Errorf("agent changed the setting of a non-service daemon: %q", desk.now())
	}
	stream <- stateEvent(daemon.Status{Service: true, SysProxy: true, Ready: true, MixedPort: 7890})
	waitFor(t, "the proxy to be set again", func() bool { return desk.now() == "127.0.0.1:7890" })

	cancel()
	<-done
	if desk.now() != "corp-proxy:3128" {
		t.Errorf("after the agent stopped the setting is %q", desk.now())
	}
	if want := []string{"enable 127.0.0.1:7890", "enable 127.0.0.1:7891", "restore corp-proxy:3128", "enable 127.0.0.1:7890", "restore corp-proxy:3128"}; !slices.Equal(desk.log, want) {
		t.Errorf("changes = %q, want %q", desk.log, want)
	}
}

// An agent that crashed while the proxy pointed at conch restores the
// user's own setting, not its own, when it starts again.
func TestAgentRepairsAfterCrash(t *testing.T) {
	desk := &desktop{setting: "corp-proxy:3128"}
	path := filepath.Join(t.TempDir(), "agent.json")
	crashed := &Agent{StatePath: path, Enable: desk.enable, Restore: desk.restore}
	crashed.follow(daemon.Status{Service: true, SysProxy: true, Ready: true, MixedPort: 7890})
	if desk.now() != "127.0.0.1:7890" {
		t.Fatal("proxy not set")
	}
	// No daemon now; the new agent puts things back.
	stub := &daemonStub{streams: make(chan chan api.Event)}
	a := &Agent{Client: stub, StatePath: path, Retry: 10 * time.Millisecond, Enable: desk.enable, Restore: desk.restore}
	ctx, cancel := context.WithCancel(context.Background())
	go a.Run(ctx)
	waitFor(t, "the repair", func() bool { return desk.now() == "corp-proxy:3128" })
	cancel()
}
