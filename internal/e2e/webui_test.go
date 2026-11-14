package e2e

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xiongnemo/conch/internal/api"
	"github.com/xiongnemo/conch/internal/auth"
	"github.com/xiongnemo/conch/internal/daemon"
	"github.com/xiongnemo/conch/web"
)

// TestWebUINodes uses the Web UI in Chrome the way people do: it pastes
// several share links at once, finds the delete button of a node with a
// very long name inside the card, and deletes the node.
//
//	CONCH_CHROME=$(command -v google-chrome)
func TestWebUINodes(t *testing.T) {
	chrome, bin := os.Getenv("CONCH_CHROME"), os.Getenv("CONCH_MIHOMO")
	if chrome == "" || bin == "" {
		t.Skip("CONCH_CHROME or CONCH_MIHOMO not set")
	}
	dir := t.TempDir()
	profile := filepath.Join(dir, "profile.yaml")
	os.WriteFile(profile, []byte(fmt.Sprintf("routes:\n  default: DIRECT\ninbound: { mixed-port: %d }\n", freePort(t))), 0o644)
	d, err := daemon.New(daemon.Options{ProfilePath: profile, DataDir: filepath.Join(dir, "data"), Backend: "mihomo", KernelBin: bin, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { d.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, "the daemon", func() bool { return d.Status().Ready })
	guard := auth.NewGuard(auth.Settings{Password: "pw", Auth: true, Listen: auth.DefaultListen})
	srv := httptest.NewServer((&api.Server{D: d, Guard: guard, Web: web.FS()}).Handler())
	t.Cleanup(srv.Close)

	b := launchChrome(t, chrome)
	p := b.open(t, srv.URL+"/")
	p.waitText(t, "#login-form", "登录")
	p.eval(t, `document.querySelector("#password").value = "pw"; document.querySelector("#login-form").requestSubmit()`)
	p.waitText(t, "header .pill", "mihomo")
	// Dialogs would block the page: answer them in it.
	p.eval(t, `window.alerts = []; window.alert = (m) => window.alerts.push(m); window.confirm = () => true;
		document.querySelector('[data-tab="outbounds"]').click()`)

	// A paste of three lines, one of them not a link.
	long := strings.Repeat("很长的名字", 40)
	paste := "socks://127.0.0.1:1081#HK%2001\nnot a link\nsocks://127.0.0.1:1082#" + long + "\n"
	p.eval(t, `document.querySelector("#node-link").focus()`)
	if err := b.call(p.session, "Input.insertText", map[string]any{"text": paste}, nil); err != nil {
		t.Fatal(err)
	}
	p.eval(t, `document.querySelector("#node-form").requestSubmit()`)
	p.waitText(t, "#nodes", "HK 01")
	p.waitText(t, "#nodes", long)
	if got := fmt.Sprint(p.eval(t, `window.alerts.join("\n")`)); !strings.Contains(got, "已添加 2 个节点") || !strings.Contains(got, "1 条无法识别") {
		t.Errorf("the page said %q", got)
	}
	p.shot(t, "webui-nodes")

	// However long the name, the delete button is inside the card.
	inside := p.eval(t, `(() => {
		const card = document.querySelector("#nodes").getBoundingClientRect();
		return [...document.querySelectorAll("#nodes .remove")].every((b) => {
			const r = b.getBoundingClientRect();
			return r.width > 0 && r.left >= card.left && r.right <= card.right;
		});
	})()`)
	if inside != true {
		t.Fatal("a delete button is outside the nodes card")
	}
	p.eval(t, `[...document.querySelectorAll("#nodes .chip")].find((c) => c.textContent.includes("很长")).querySelector(".remove").click()`)
	waitFor(t, "the node to go", func() bool {
		return !strings.Contains(fmt.Sprint(p.eval(t, `document.querySelector("#nodes").textContent`)), "很长")
	})
	if got := fmt.Sprint(p.eval(t, `document.querySelector("#nodes").textContent`)); !strings.Contains(got, "HK 01") {
		t.Errorf("nodes left: %q", got)
	}
}
