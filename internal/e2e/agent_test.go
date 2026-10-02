package e2e

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/xiongnemo/conch/internal/agent"
	"github.com/xiongnemo/conch/internal/api"
	"github.com/xiongnemo/conch/internal/auth"
	"github.com/xiongnemo/conch/internal/daemon"
	"github.com/xiongnemo/conch/internal/platform/sysproxy"
)

// TestServiceAgent runs a daemon in service mode with an agent beside it:
// the daemon leaves the system proxy alone, the agent sets and restores it.
func TestServiceAgent(t *testing.T) {
	bin := os.Getenv("CONCH_MIHOMO")
	if bin == "" {
		t.Skip("CONCH_MIHOMO not set")
	}
	dir := t.TempDir()
	profile := filepath.Join(dir, "profile.yaml")
	port := freePort(t)
	os.WriteFile(profile, []byte(fmt.Sprintf("routes: { default: DIRECT }\ninbound: { mixed-port: %d }\n", port)), 0o644)
	d, err := daemon.New(daemon.Options{ProfilePath: profile, DataDir: filepath.Join(dir, "data"), Backend: "mihomo", KernelBin: bin, Offline: true, Service: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { d.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, "the daemon", func() bool { return d.Status().Ready })

	guard := auth.NewGuard(auth.Settings{Password: "pw", Auth: true, Listen: auth.DefaultListen})
	srv := httptest.NewServer((&api.Server{D: d, Guard: guard}).Handler())
	c := &api.Client{Base: srv.URL, Password: "pw", HTTP: srv.Client()}

	var mu sync.Mutex
	setting := "user's own"
	now := func() string { mu.Lock(); defer mu.Unlock(); return setting }
	a := &agent.Agent{Client: c, StatePath: filepath.Join(dir, "agent.json"), Retry: 50 * time.Millisecond,
		Enable: func(p int) (sysproxy.Snapshot, error) {
			mu.Lock()
			defer mu.Unlock()
			prev := setting
			setting = fmt.Sprintf("127.0.0.1:%d", p)
			return sysproxy.Snapshot(prev), nil
		},
		Restore: func(s sysproxy.Snapshot) error { mu.Lock(); setting = string(s); mu.Unlock(); return nil },
	}
	agentCtx, stopAgent := context.WithCancel(context.Background())
	agentDone := make(chan struct{})
	go func() { a.Run(agentCtx); close(agentDone) }()
	t.Cleanup(func() { stopAgent(); <-agentDone })

	if err := c.SetSysProxy(ctx, true); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the agent to set the proxy", func() bool { return now() == fmt.Sprintf("127.0.0.1:%d", port) })
	if err := c.SetSysProxy(ctx, false); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the agent to restore", func() bool { return now() == "user's own" })

	// When the service stops, the agent puts the user's setting back.
	c.SetSysProxy(ctx, true)
	waitFor(t, "the proxy again", func() bool { return now() != "user's own" })
	srv.CloseClientConnections()
	srv.Close()
	waitFor(t, "the restore after the daemon went away", func() bool { return now() == "user's own" })
}
