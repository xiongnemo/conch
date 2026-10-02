package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// conch init writes a profile that compiles, from either kind of
// subscription and without one, and never overwrites a profile unasked.
func TestInit(t *testing.T) {
	clash := "proxies:\n  - { name: 香港, type: socks5, server: 192.0.2.1, port: 1 }\n" +
		"proxy-groups:\n  - { name: 代理, type: select, proxies: [香港] }\n" +
		"rules:\n  - DOMAIN-SUFFIX,cn,DIRECT\n  - MATCH,代理\n"
	links := "socks5://192.0.2.1:1080#一\nsocks5://192.0.2.2:1080#二\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, map[string]string{"/clash": clash, "/links": links}[r.URL.Path])
	}))
	defer srv.Close()

	for _, tt := range []struct {
		name, url, want string
	}{
		{"no subscription", "", "DIRECT"},
		{"clash config", srv.URL + "/clash", "代理"}, // the subscription's MATCH
		{"share links", srv.URL + "/links", "节点选择"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("CONCH_CONFIG_DIR", t.TempDir())
			t.Setenv("CONCH_DATA_DIR", t.TempDir())
			args := []string{}
			if tt.url != "" {
				args = append(args, tt.url)
			}
			run := func(args ...string) error {
				cmd := newInitCmd()
				cmd.SetArgs(args)
				cmd.SetOut(io.Discard)
				cmd.SetErr(io.Discard)
				return cmd.ExecuteContext(context.Background())
			}
			if err := run(args...); err != nil {
				t.Fatal(err)
			}
			profile := filepath.Join(os.Getenv("CONCH_CONFIG_DIR"), "profile.yaml")
			if err := run(args...); err == nil || !strings.Contains(err.Error(), "--force") {
				t.Errorf("a second init: %v, want a refusal", err)
			}

			// Offline: the first download is in the daemon's cache.
			pl := pipeline{profilePath: profile, offline: true, log: io.Discard}
			res, diags, err := pl.compile(context.Background())
			if err != nil || diags.HasErrors() {
				t.Fatalf("the profile does not compile: %v %v", err, diags)
			}
			if got := res.Rules[len(res.Rules)-1].Target; got != tt.want {
				t.Errorf("default exit %q, want %q", got, tt.want)
			}
			if fi, err := os.Stat(profile); err == nil && runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
				t.Errorf("profile mode %v: the subscription URL is a secret", fi.Mode())
			}
		})
	}
}

func TestInitForceKeepsABackup(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CONCH_CONFIG_DIR", dir)
	profile := filepath.Join(dir, "profile.yaml")
	os.WriteFile(profile, []byte("mine\n"), 0o600)
	cmd := newInitCmd()
	cmd.SetArgs([]string{"--force"})
	cmd.SetOut(io.Discard)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if old, _ := os.ReadFile(profile + ".bak"); !bytes.Equal(old, []byte("mine\n")) {
		t.Errorf("backup = %q", old)
	}
}
