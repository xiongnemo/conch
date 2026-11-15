package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xiongnemo/conch/internal/nodeform"
)

// The check says what the running kernel would: xray refuses VLESS
// without encryption to a public server, and warns of what it drops.
func TestCheckNodesSpeaksForTheKernel(t *testing.T) {
	dir := t.TempDir()
	profile := filepath.Join(dir, "profile.yaml")
	os.WriteFile(profile, []byte("routes: { default: DIRECT }\n"), 0o644)
	d, err := New(Options{ProfilePath: profile, DataDir: filepath.Join(dir, "data"), Backend: "xray", KernelBin: "xray-is-not-run"})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		node, want string
		isErr      bool
	}{
		{"{ name: v, type: vless, server: 203.0.114.1, port: 80, uuid: 11111111-2222-3333-4444-555555555555 }", "xray 不允许 VLESS 不加密", true},
		{"{ name: s, type: ss, server: 203.0.114.1, port: 8388, cipher: aes-128-gcm, password: p, udp-over-tcp: true }", "UDP over TCP", false},
		{"{ name: t, type: trojan, server: t.example, port: 443, password: p }", "", false},
		{"{ name: DIRECT, type: trojan, server: t.example, port: 443, password: p }", "已经有叫", true},
	} {
		nodes, err := nodeform.Parse(c.node)
		if err != nil {
			t.Fatal(err)
		}
		got := d.CheckNodes(nodes, "")
		said := strings.Join(append(got.Errors, got.Warnings...), "; ")
		if c.isErr != (len(got.Errors) > 0) || c.want == "" && said != "" || !strings.Contains(said, c.want) {
			t.Errorf("%s: errors %q, warnings %q; want %q", c.node, got.Errors, got.Warnings, c.want)
		}
		if strings.Contains(said, `节点 "`) {
			t.Errorf("%s: messages name the node the form is about: %s", c.node, said)
		}
	}
}
