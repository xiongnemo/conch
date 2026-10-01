package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// With a daemon running, `sub update` asks it to update: the daemon
// fetches through its kernel and applies the new nodes at once.
func TestSubUpdateThroughDaemon(t *testing.T) {
	var updated []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/subscriptions/机场/update":
			updated = append(updated, r.Method)
			w.Write([]byte(`{}`))
		case "/api/v1/status":
			w.Write([]byte(`{"subscriptions":{"机场":{"fetchedAt":"2026-10-02T01:00:00Z","summary":"3 个节点，1 个出口组，2 条规则"}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "profile.yaml"), []byte("subscriptions:\n  - { name: 机场, url: https://example.com/sub }\n"), 0o644)
	t.Chdir(t.TempDir())
	t.Setenv("NAUTILUS_CONFIG_DIR", dir)
	t.Setenv("NAUTILUS_DATA_DIR", t.TempDir())
	t.Setenv("NAUTILUS_LISTEN", strings.TrimPrefix(srv.URL, "http://"))
	t.Setenv("NAUTILUS_PASSWORD", "x")

	cmd := newSubCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"update"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err, out.String())
	}
	if len(updated) != 1 || updated[0] != http.MethodPost || !strings.Contains(out.String(), "机场：3 个节点，1 个出口组，2 条规则") {
		t.Errorf("update calls %v, output:\n%s", updated, out.String())
	}
}
