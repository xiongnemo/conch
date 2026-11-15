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

// webUIOutbounds starts a daemon with mihomo and the Web UI, logs in
// with Chrome and opens the outbounds page.
func webUIOutbounds(t *testing.T) (*browser, *tab) {
	t.Helper()
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
	// The login form is in the page before the script that handles it
	// runs; the script shows it once it asked for a session.
	waitFor(t, "the login form", func() bool { return p.eval(t, `document.querySelector("#login")?.hidden === false`) == true })
	p.eval(t, `document.querySelector("#password").value = "pw"; document.querySelector("#login-form").requestSubmit()`)
	p.waitText(t, "header .pill", "运行中")
	// The kernel can be switched from the header.
	p.waitText(t, "#backend", "sing-box")
	if got := p.eval(t, `document.querySelector("#backend").value`); got != "mihomo" {
		t.Errorf("the kernel selector shows %v", got)
	}
	// Dialogs would block the page: answer them in it.
	p.eval(t, `window.alerts = []; window.alert = (m) => window.alerts.push(m); window.confirm = () => true;
		document.querySelector('#tabs [data-tab="outbounds"]').click()`)
	return b, p
}

// TestWebUINodes uses the Web UI in Chrome the way people do: it pastes
// several share links at once, finds the delete button of a node with a
// very long name inside the card, and deletes the node.
//
//	CONCH_CHROME=$(command -v google-chrome)
func TestWebUINodes(t *testing.T) {
	b, p := webUIOutbounds(t)

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

// TestWebUINodeForm writes nodes by hand: in the form, where the fields
// follow the protocol and the daemon checks what is typed, then as YAML,
// and edits one it added.
func TestWebUINodeForm(t *testing.T) {
	_, p := webUIOutbounds(t)
	// set types into an input the way a person does, so its events fire.
	set := func(sel, value string) {
		t.Helper()
		p.eval(t, fmt.Sprintf(`(() => {
			const el = document.querySelector(%q);
			el.value = %q;
			el.dispatchEvent(new Event(el.tagName === "SELECT" ? "change" : "input", { bubbles: true }));
		})()`, sel, value))
	}
	text := func(sel string) string {
		return fmt.Sprint(p.eval(t, fmt.Sprintf(`document.querySelector(%q).textContent`, sel)))
	}

	p.eval(t, `document.querySelector('.tabs [data-editor="form"]').click()`)
	p.waitText(t, "#node-field-list", "加密方式") // Shadowsocks comes first
	set("#nf-type", "vless")
	p.waitText(t, "#node-field-list", "UUID")
	if got := text("#node-field-list"); strings.Contains(got, "加密方式") || strings.Contains(got, "REALITY") {
		t.Errorf("vless without TLS shows %q", got)
	}
	set("#nf-name", "表单节点")
	set("#nf-server", "127.0.0.1")
	p.waitText(t, "#node-check", "还要填：端口、UUID")

	// A SOCKS5 node, then, which the running mihomo takes.
	set("#nf-type", "socks5")
	p.waitText(t, "#node-field-list", "用户名")
	set("#nf-port", "1083")
	p.waitText(t, "#node-check", "{name: 表单节点, type: socks5, server: 127.0.0.1, port: 1083, udp: true}")
	p.eval(t, `document.querySelector("#nf-tls").click(); document.querySelector("#nodes-card").scrollIntoView()`)
	p.waitText(t, "#node-field-list", "跳过证书校验")
	p.shotAt(t, "webui-node-form", 1100, 900)
	p.shot(t, "webui-node-form-narrow")
	p.eval(t, `document.querySelector("#nf-tls").click()`)
	p.eval(t, `document.querySelector("#node-fields").requestSubmit()`)
	p.waitText(t, "#node-check", "已添加节点 表单节点")
	p.waitText(t, "#nodes", "表单节点")

	// Edited: renamed, another port.
	p.eval(t, `[...document.querySelectorAll("#nodes .chip")].find((c) => c.textContent.includes("表单节点")).querySelector(".edit").click()`)
	p.waitText(t, "#node-editing", "表单节点")
	if got := p.eval(t, `document.querySelector("#nf-port").value`); got != "1083" {
		t.Fatalf("the form shows port %v", got)
	}
	set("#nf-name", "改过的节点")
	set("#nf-port", "1084")
	p.waitText(t, "#node-check", "port: 1084")
	p.eval(t, `document.querySelector("#node-fields").requestSubmit()`)
	p.waitText(t, "#node-check", "已保存节点 改过的节点")
	p.waitText(t, "#nodes", "改过的节点")
	if strings.Contains(text("#nodes"), "表单节点") {
		t.Error("the old name is still there")
	}

	// Two nodes as YAML at once; the form cannot hold two.
	p.eval(t, `document.querySelector('.tabs [data-editor="yaml"]').click()`)
	waitFor(t, "the YAML tab", func() bool { return p.eval(t, `!document.querySelector("#node-yaml-form").hidden`) == true })
	if got := p.eval(t, `document.querySelector("#node-yaml").value`); got != "" {
		t.Errorf("an untouched form went to the YAML tab as %q", got)
	}
	set("#node-yaml", "- { name: Y1, type: socks5, server: 127.0.0.1, port: 1085 }\n- { name: Y2, type: http, server: 127.0.0.1, port: 1086 }\n")
	p.eval(t, `document.querySelector('.tabs [data-editor="form"]').click()`)
	p.waitText(t, "#node-check", "表单一次只能填一个")
	p.eval(t, `document.querySelector("#node-yaml-form").requestSubmit()`)
	p.waitText(t, "#node-check", "已添加节点 Y1、Y2")
	p.waitText(t, "#nodes", "Y2")

	// A name that is taken is said before saving.
	set("#node-yaml", "{ name: Y1, type: socks5, server: 127.0.0.1, port: 1087 }")
	p.waitText(t, "#node-check", `已经有叫 "Y1" 的出口了`)
}
