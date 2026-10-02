package subscription

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/xiongnemo/conch/internal/model"
)

// A subscription that cannot be downloaded directly comes through the
// kernel; one that can is never sent through it.
func TestDownloadThroughKernel(t *testing.T) {
	const body = "proxies:\n  - { name: a, type: socks5, server: 192.0.2.1, port: 1 }\n"
	var proxied atomic.Int32
	kernel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied.Add(1)
		w.Write([]byte(body))
	}))
	defer kernel.Close()
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
	defer direct.Close()
	via, _ := url.Parse(kernel.URL)
	s := &Store{Dir: t.TempDir(), Proxy: func() *url.URL { return via }}
	ctx := context.Background()

	if _, _, err := s.Update(ctx, &model.Subscription{Name: "ok", URL: direct.URL}); err != nil || proxied.Load() != 0 {
		t.Fatalf("direct download: %v (%d proxied)", err, proxied.Load())
	}
	snap, _, err := s.Update(ctx, &model.Subscription{Name: "blocked", URL: "http://blocked.invalid/sub"})
	if err != nil || len(snap.Nodes) != 1 || proxied.Load() != 1 {
		t.Fatalf("through the kernel: %v (%d proxied)", err, proxied.Load())
	}
}
