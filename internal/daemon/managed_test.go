package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/xiongnemo/conch/internal/backend/xray"
	"github.com/xiongnemo/conch/internal/control"
	"github.com/xiongnemo/conch/internal/kernel"
	"github.com/xiongnemo/conch/internal/subscription"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xiongnemo/conch/internal/model"
)

// Routes from managed.yaml say where they are written; temporary ones
// until when they last, in the words the UIs use.
func TestMergeEntries(t *testing.T) {
	p := &model.Profile{}
	p.Routes.Entries = []*model.Entry{{Key: "example.com", Via: model.Via{Name: "A"}}}
	m := &managed{Entries: []managedEntry{{Key: "example.org", Via: "B"}}}
	until := time.Date(2026, 10, 2, 15, 4, 0, 0, time.Local)
	mergeEntries(p, m, []TempRoute{{Key: "example.com", Via: "C", Expires: until}}, "/cfg/managed.yaml")

	got := map[string]string{}
	for _, e := range p.Routes.Entries {
		got[e.Key] = e.Via.Name + " @ " + e.Pos.String()
	}
	want := map[string]string{"example.com": "C @ 临时条目，到 15:04", "example.org": "B @ /cfg/managed.yaml"}
	if len(got) != len(want) || got["example.com"] != want["example.com"] || got["example.org"] != want["example.org"] {
		t.Errorf("entries = %v, want %v", got, want)
	}
}

// Unix socket paths may not be much longer than 100 bytes on any OS.
func TestSocketDir(t *testing.T) {
	base := filepath.Join(string(filepath.Separator)+"home", "u", "conch")
	if got := socketDir(base); got != filepath.Join(base, "run") {
		t.Errorf("socketDir(%s) = %s", base, got)
	}
	deep := filepath.Join(append([]string{base}, slices.Repeat([]string{"deep"}, 20)...)...)
	got := socketDir(deep)
	if len(filepath.Join(got, "xray-probe-4.sock")) > 100 || got != socketDir(deep) || strings.HasPrefix(got, deep) {
		t.Errorf("socketDir(%s) = %s", deep, got)
	}
}

type fakeCaps struct{ control.Kernel }

func (fakeCaps) Caps() control.Caps { return control.Caps{} }

// The API encodes a status after the lock is released while subscription
// updates keep writing: it must hold copies (go test -race).
func TestStatusSubscriptionsAreCopies(t *testing.T) {
	d := testDaemon(t, 7890)
	d.backend, d.ctl, d.sup = xray.Backend{}, fakeCaps{}, kernel.NewSupervisor()
	d.subInfo = map[string]*subscription.Info{"a": {Download: 1}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 2000 {
			d.mu.Lock()
			d.subInfo[fmt.Sprint("s", i%7)] = &subscription.Info{Download: int64(i)}
			d.subInfo["a"].Download++
			d.mu.Unlock()
		}
	}()
	for range 200 {
		if _, err := json.Marshal(d.Status()); err != nil {
			t.Fatal(err)
		}
	}
	<-done
}

// A subscription that fails, also one never downloaded, is tried again
// after a minute, then less and less often, not on every tick.
func TestSubscriptionRetry(t *testing.T) {
	down := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprint(w, "proxies:\n  - { name: a, type: socks5, server: 192.0.2.1, port: 1 }\n")
	}))
	defer srv.Close()
	d := testDaemon(t, 7890)
	d.subs = &subscription.Store{Dir: t.TempDir()}
	d.subInfo, d.subRetry = map[string]*subscription.Info{}, map[string]subRetry{}
	d.profile = &model.Profile{Subscriptions: []*model.Subscription{{Name: "s", URL: srv.URL}}}
	ctx, now := context.Background(), time.Now()
	if d.refreshSubscriptions(ctx, now) || d.subRetry["s"].wait != time.Minute {
		t.Fatalf("after a failure: retry %+v", d.subRetry["s"])
	}
	if d.refreshSubscriptions(ctx, now.Add(10*time.Second)); d.subRetry["s"].wait != time.Minute {
		t.Fatalf("tried again before the minute: %+v", d.subRetry["s"])
	}
	if d.refreshSubscriptions(ctx, now.Add(61*time.Second)); d.subRetry["s"].wait != 2*time.Minute {
		t.Fatalf("second failure: %+v", d.subRetry["s"])
	}
	down = false
	if !d.refreshSubscriptions(ctx, now.Add(4*time.Minute)) || d.subInfo["s"] == nil {
		t.Fatal("no update once the provider is back")
	}
	if _, ok := d.subRetry["s"]; ok {
		t.Error("the retry was not forgotten after success")
	}
}
