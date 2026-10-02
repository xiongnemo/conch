package lists

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xiongnemo/conch/internal/route"
)

// A list that cannot be downloaded directly comes through the kernel.
func TestDownloadThroughKernel(t *testing.T) {
	var proxied atomic.Int32
	kernel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied.Add(1) // an HTTP proxy gets the whole URL
		if r.URL.Host != "blocked.invalid" {
			http.Error(w, "unexpected "+r.URL.String(), http.StatusBadGateway)
			return
		}
		w.Write([]byte("+.example.com\n"))
	}))
	defer kernel.Close()
	via, _ := url.Parse(kernel.URL)
	p := route.Provider{Name: "x", Behavior: "domain", Format: "text", URL: "http://blocked.invalid/list.txt"}

	if _, _, err := (&Store{Dir: t.TempDir()}).Load(context.Background(), p); err == nil {
		t.Fatal("without the kernel the download must fail")
	}
	s := &Store{Dir: t.TempDir(), Proxy: func() *url.URL { return via }}
	if entries, _, err := s.Load(context.Background(), p); err != nil || len(entries) != 1 || proxied.Load() != 1 {
		t.Fatalf("Load through the kernel = %v, %v (%d proxied)", entries, err, proxied.Load())
	}
}

func TestRefresh(t *testing.T) {
	var body atomic.Value
	body.Store("+.example.com\n")
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if b := body.Load().(string); b != "" {
			w.Write([]byte(b))
			return
		}
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	ctx, now := context.Background(), time.Now()
	used := route.Provider{Name: "x", Behavior: "domain", Format: "text", URL: srv.URL + "/a.txt"}
	never := route.Provider{Name: "y", Behavior: "domain", Format: "text", URL: srv.URL + "/b.txt"}
	s := &Store{Dir: t.TempDir()}
	if _, _, err := s.Load(ctx, used); err != nil {
		t.Fatal(err)
	}
	ps := []route.Provider{used, never}

	if s.Refresh(ctx, ps, 24*time.Hour, now.Add(time.Hour)) || hits.Load() != 1 {
		t.Fatalf("a fresh list was downloaded again (%d downloads)", hits.Load())
	}
	if s.Refresh(ctx, ps, 24*time.Hour, now.Add(25*time.Hour)) || hits.Load() != 2 {
		t.Fatalf("a day-old list: changed or not downloaded once (%d downloads)", hits.Load())
	}
	body.Store("+.example.com\n+.example.org\n")
	if !s.Refresh(ctx, ps, 24*time.Hour, now.Add(50*time.Hour)) {
		t.Fatal("new content not reported")
	}
	if entries, _, _ := s.Load(ctx, used); len(entries) != 2 {
		t.Fatalf("cache has %d entries, want 2", len(entries))
	}

	// A failure is tried again an hour later, not at every tick.
	body.Store("")
	failAt := now.Add(80 * time.Hour)
	s.Refresh(ctx, ps, 24*time.Hour, failAt)
	n := hits.Load()
	if s.Refresh(ctx, ps, 24*time.Hour, failAt.Add(time.Minute)); hits.Load() != n {
		t.Error("a failed list was tried again at once")
	}
	if s.Refresh(ctx, ps, 24*time.Hour, failAt.Add(61*time.Minute)); hits.Load() != n+1 {
		t.Error("a failed list was not tried again after an hour")
	}
	if _, err := os.Stat(s.path(never)); err == nil {
		t.Error("a list never used was downloaded")
	}
}
