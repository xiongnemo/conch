package e2e

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xiongnemo/conch/internal/api"
	"github.com/xiongnemo/conch/internal/auth"
	"github.com/xiongnemo/conch/internal/daemon"
	"github.com/xiongnemo/conch/internal/platform/privilege"
	"github.com/xiongnemo/conch/web"
)

// TestAPI runs the HTTP API against a real daemon: authentication, the
// operations the Web UI uses, and the event stream.
func TestAPI(t *testing.T) {
	bin := os.Getenv("CONCH_MIHOMO")
	if bin == "" {
		t.Skip("CONCH_MIHOMO not set")
	}
	dir := t.TempDir()
	profile := filepath.Join(dir, "profile.yaml")
	os.WriteFile(profile, []byte(fmt.Sprintf(`
nodes:
  - { name: n1, type: socks5, server: 127.0.0.1, port: 1 }
  - { name: n2, type: socks5, server: 127.0.0.1, port: 2 }
groups:
  - { name: 选择, type: select, members: [n1, n2] }
routes:
  default: 选择
  entries:
    example.org: DIRECT
inbound: { mixed-port: %d }
`, freePort(t))), 0o644)
	d, err := daemon.New(daemon.Options{ProfilePath: profile, DataDir: filepath.Join(dir, "data"), Backend: "mihomo", KernelBin: bin, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { d.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	guard := auth.NewGuard(auth.Settings{Password: "secret", Auth: true, Listen: auth.DefaultListen})
	srv := httptest.NewServer((&api.Server{D: d, Guard: guard, Web: web.FS()}).Handler())
	t.Cleanup(srv.Close)
	c := &api.Client{Base: srv.URL, Password: "secret", HTTP: srv.Client()}

	for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if s, err := c.Status(ctx); err == nil && s.Ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("daemon not ready")
		}
	}

	// Without the password nothing but the login page and assets.
	anon := &api.Client{Base: srv.URL, HTTP: srv.Client()}
	var apiErr *api.APIError
	if _, err := anon.Status(ctx); !errors.As(err, &apiErr) || apiErr.Status != http.StatusUnauthorized {
		t.Errorf("anonymous status: %v", err)
	}
	if resp, err := srv.Client().Get(srv.URL + "/"); err != nil || resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "default-src 'self'") {
		t.Errorf("web UI: %v %v", resp, err)
	}

	// The kernel config as applied, for a browser tab.
	compiled, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/compiled", nil)
	compiled.Header.Set("Authorization", "Bearer secret")
	if resp, err := srv.Client().Do(compiled); err != nil || resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") {
		t.Errorf("compiled config: %v %v", resp, err)
	} else {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(body), "mixed-port:") {
			t.Errorf("compiled config is not mihomo's:\n%.200s", body)
		}
	}

	out, err := c.Outbounds(ctx)
	if err != nil || len(out) < 5 {
		t.Fatalf("outbounds = %v, %v", out, err)
	}
	if err := c.Select(ctx, "选择", "n2"); err != nil {
		t.Fatal(err)
	}
	if err := c.Select(ctx, "选择", "nope"); err == nil {
		t.Error("selecting a non-member must fail")
	}

	// Routes the user wrote in profile.yaml are not ours to change.
	err = c.SetRoute(ctx, "example.org", "n1", 0)
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusConflict || !strings.Contains(apiErr.Body.Where, "profile.yaml:10") {
		t.Errorf("setting a profile route: %v", err)
	}
	if err := c.SetRoute(ctx, "chatgpt.com", "n1", 0); err != nil {
		t.Fatal(err)
	}
	if err := c.SetRoute(ctx, "claude.ai", "n2", time.Hour); err != nil {
		t.Fatal(err)
	}
	table, err := c.Routes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var managed, temp bool
	for _, e := range table.Domains {
		managed = managed || (e.Target == "chatgpt.com" && e.Managed && e.Expires == nil)
		temp = temp || (e.Target == "claude.ai" && e.Expires != nil)
	}
	if !managed || !temp {
		t.Errorf("routes table = %+v", table.Domains)
	}
	ex, err := c.Explain(ctx, "chat.chatgpt.com", "")
	if err != nil || ex.Target != "n1" || !strings.Contains(ex.Matched, "chatgpt.com") {
		t.Errorf("explain = %+v, %v", ex, err)
	}
	if err := c.DeleteRoute(ctx, "claude.ai"); err != nil {
		t.Error(err)
	}
	if err := c.DeleteRoute(ctx, "example.org"); !errors.As(err, &apiErr) || apiErr.Status != http.StatusConflict {
		t.Errorf("deleting a profile route: %v", err)
	}

	// Changes show up on the event stream.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/v1/events", nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	events := make(chan string, 16)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if name, ok := strings.CutPrefix(sc.Text(), "event: "); ok {
				events <- name
			}
		}
	}()
	if first := <-events; first != "state" {
		t.Errorf("first event = %q, want the current state", first)
	}
	if err := c.SetMode(ctx, "global"); err != nil {
		t.Fatal(err)
	}
	timeout := time.After(10 * time.Second)
	for got := ""; got != "state"; {
		select {
		case got = <-events:
		case <-timeout:
			t.Fatal("no state event after changing the mode")
		}
	}
	if s, _ := c.Status(ctx); s.Mode != "global" {
		t.Errorf("mode = %q after switching to global", s.Mode)
	}

	// Without the privilege, TUN is refused with a way to get it, and
	// nothing changes.
	if privilege.TUNError(bin) != nil {
		err := c.SetTUN(ctx, true)
		if !errors.As(err, &apiErr) || !strings.Contains(apiErr.Body.Error, "sudo setcap cap_net_admin") {
			t.Errorf("TUN without privileges: %v", err)
		}
		if s, _ := c.Status(ctx); s.TUN || s.Error != "" {
			t.Errorf("status after refused TUN: tun %v, error %q", s.TUN, s.Error)
		}
	}
}
