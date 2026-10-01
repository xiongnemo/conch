package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"nautilus/internal/api"
	"nautilus/internal/auth"
	"nautilus/internal/daemon"
	"nautilus/web"
)

// TestExtension loads the browser extension into Chrome, pairs it with a
// daemon and uses its popup: it explains the site in a tab, routes it
// elsewhere, and lists the hosts the page failed to load.
//
//	NAUTILUS_CHROME=$(command -v google-chrome) NAUTILUS_EXTENSION=$PWD/extension/dist/chrome
func TestExtension(t *testing.T) {
	chrome, ext, bin := os.Getenv("NAUTILUS_CHROME"), os.Getenv("NAUTILUS_EXTENSION"), os.Getenv("NAUTILUS_MIHOMO")
	if chrome == "" || ext == "" || bin == "" {
		t.Skip("NAUTILUS_CHROME, NAUTILUS_EXTENSION or NAUTILUS_MIHOMO not set")
	}
	extDir := grantAllSites(t, ext)

	// A page whose script comes from a host that refuses connections.
	closed := freePort(t)
	site := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<!doctype html><title>site</title><script src="http://127.0.0.3:%d/missing.js"></script>ok`, closed)
	})}
	ln, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skip("cannot listen on 127.0.0.2:", err)
	}
	go site.Serve(ln)
	t.Cleanup(func() { site.Close() })
	siteURL := "http://" + ln.Addr().String() + "/"

	dir := t.TempDir()
	profile := filepath.Join(dir, "profile.yaml")
	os.WriteFile(profile, []byte(fmt.Sprintf(`
nodes:
  - { name: dead, type: socks5, server: 127.0.0.1, port: 1 }
groups:
  - { name: 选择, type: select, members: [dead, DIRECT] }
routes:
  default: DIRECT
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
	waitFor(t, "the daemon", func() bool { return d.Status().Ready })

	guard := auth.NewGuard(auth.Settings{Password: "secret", Auth: true, Listen: auth.DefaultListen})
	if guard.Pairings, err = auth.LoadPairings(filepath.Join(dir, "pairings.json")); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer((&api.Server{D: d, Guard: guard, Web: web.FS()}).Handler())
	t.Cleanup(srv.Close)

	b := launchChrome(t, chrome)
	var loaded struct {
		ID string `json:"id"`
	}
	if err := b.call("", "Extensions.loadUnpacked", map[string]any{"path": extDir}, &loaded); errors.Is(err, errNoReply) {
		b.fatal(t, err)
	} else if err != nil {
		t.Skip("this Chrome cannot load unpacked extensions:", err)
	}
	if err := b.call("", "Browser.grantPermissions", map[string]any{"permissions": []string{"localNetworkAccess"}, "origin": "chrome-extension://" + loaded.ID}, nil); err != nil {
		t.Log("cannot grant the extension local network access:", err) // older Chrome does not ask for it
	}
	sitePage := b.open(t, siteURL)
	popup := b.open(t, "chrome-extension://"+loaded.ID+"/popup.html")

	// Pair with a code, as a user copies it from `nautilus pair`.
	popup.waitText(t, "form.pair", "nautilus pair")
	popup.shot(t, "popup-pair")
	code, _ := guard.Pairings.NewCode(time.Now())
	popup.eval(t, fmt.Sprintf(`document.querySelector("#base").value = %q; document.querySelector("#code").value = %q;
		document.querySelector("form.pair").requestSubmit()`, srv.URL, code))
	popup.waitText(t, "header .pill", "mihomo")
	if list := guard.Pairings.List(); len(list) != 1 || list[0].Origin != "chrome-extension://"+loaded.ID {
		t.Fatalf("pairings = %+v", list)
	}

	// Show the popup for the site's tab.
	tabID := popup.eval(t, fmt.Sprintf(`chrome.tabs.query({}).then((tabs) => String(tabs.find((t) => t.url === %q)?.id))`, siteURL))
	popup.eval(t, fmt.Sprintf(`location.hash = "tab=%s"; location.reload()`, tabID))
	popup.waitText(t, ".site .via b", "DIRECT")
	popup.waitText(t, ".site", "命中：")
	popup.shot(t, "popup-site")

	// Send the site elsewhere for an hour.
	popup.eval(t, `document.querySelector("#via").value = "选择"; document.querySelector("#ttl").value = "1h";
		document.querySelector("form.route").requestSubmit()`)
	popup.waitText(t, ".notice", "已让 127.0.0.2 走 选择")
	popup.waitText(t, ".site .via b", "选择")
	if temp := d.Temp(); len(temp) != 1 || temp[0].Key != "127.0.0.2" || temp[0].Via != "选择" {
		t.Errorf("temporary routes = %+v", temp)
	}
	// Undo it.
	popup.eval(t, `document.querySelector(".notice button").click()`)
	popup.waitText(t, ".site .via b", "DIRECT")
	if temp := d.Temp(); len(temp) != 0 {
		t.Errorf("undo left %+v", temp)
	}

	// The script that failed to load is listed, and can be routed. The
	// page is loaded again now that the extension's worker surely runs.
	sitePage.eval(t, `location.reload()`)
	time.Sleep(500 * time.Millisecond)
	popup.eval(t, `location.reload()`)
	popup.waitText(t, ".failures", "127.0.0.3")
	popup.waitText(t, ".failures", "连接被拒绝")
	popup.shot(t, "popup-failures")
	popup.eval(t, `document.querySelector(".failures button").click()`)
	popup.waitText(t, ".site .host", "127.0.0.3")

	// Revoking the pairing locks the extension out.
	guard.Pairings.Revoke(guard.Pairings.List()[0].ID)
	popup.eval(t, `location.reload()`)
	popup.waitText(t, "form.pair", "配对已失效")
}

// grantAllSites copies the extension, asking for every site up front: a
// test cannot click the permission prompt the popup would show.
func grantAllSites(t *testing.T, ext string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "extension")
	if err := os.CopyFS(dst, os.DirFS(ext)); err != nil {
		t.Fatalf("copy %s: %v (build it with npm run build in extension/)", ext, err)
	}
	path := filepath.Join(dst, "manifest.json")
	var m map[string]any
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	m["host_permissions"] = append(m["host_permissions"].([]any), "<all_urls>")
	data, _ = json.Marshal(m)
	os.WriteFile(path, data, 0o644)
	return dst
}

// browser speaks the DevTools protocol over the pipe Chrome opens with
// --remote-debugging-pipe, the only transport that may load extensions.
type browser struct {
	w       io.Writer
	log     string // Chrome's stderr
	mu      sync.Mutex
	next    int
	pending map[int]chan cdpReply
}

var errNoReply = errors.New("no reply")

// fatal fails the test with the end of Chrome's log.
func (b *browser) fatal(t *testing.T, err error) {
	t.Helper()
	data, _ := os.ReadFile(b.log)
	if len(data) > 4000 {
		data = data[len(data)-4000:]
	}
	t.Fatalf("%v; Chrome's log ends with:\n%s", err, data)
}

type cdpReply struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func launchChrome(t *testing.T, bin string) *browser {
	t.Helper()
	toChrome, chromeIn, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	chromeOut, fromChrome, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "--headless=new", "--remote-debugging-pipe", "--enable-unsafe-extension-debugging",
		"--user-data-dir="+t.TempDir(), "--no-first-run", "--no-default-browser-check", "--disable-gpu", "--no-sandbox", "--no-proxy-server",
		// Cookies wait for the OS keyring otherwise, stalling requests for seconds.
		"--password-store=basic", "about:blank")
	cmd.ExtraFiles = []*os.File{toChrome, fromChrome} // fd 3: commands in, fd 4: replies out
	log, err := os.Create(filepath.Join(t.TempDir(), "chrome.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd.Stderr = log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	toChrome.Close()
	fromChrome.Close()
	b := &browser{w: chromeIn, log: log.Name(), pending: map[int]chan cdpReply{}}
	t.Cleanup(func() {
		// Closing lets Chrome's helper processes finish writing to the
		// profile before the test removes it.
		exited := make(chan struct{})
		go func() { cmd.Wait(); close(exited) }()
		b.call("", "Browser.close", map[string]any{}, nil)
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
			<-exited
		}
	})
	go func() {
		r := bufio.NewReader(chromeOut)
		for {
			msg, err := r.ReadBytes(0)
			if err != nil {
				return
			}
			var v struct {
				ID int `json:"id"`
				cdpReply
			}
			if json.Unmarshal(msg[:len(msg)-1], &v) != nil || v.ID == 0 {
				continue // an event
			}
			b.mu.Lock()
			ch := b.pending[v.ID]
			delete(b.pending, v.ID)
			b.mu.Unlock()
			if ch != nil {
				ch <- v.cdpReply
			}
		}
	}()
	// The first start on a fresh machine can take a while, building caches.
	var version struct {
		Product string `json:"product"`
	}
	for start := time.Now(); ; {
		err := b.call("", "Browser.getVersion", map[string]any{}, &version)
		if err == nil {
			break
		}
		if !errors.Is(err, errNoReply) || time.Since(start) > time.Minute {
			b.fatal(t, fmt.Errorf("Chrome did not start: %w", err))
		}
	}
	t.Log(version.Product)
	return b
}

func (b *browser) call(session, method string, params, result any) error {
	b.mu.Lock()
	b.next++
	id := b.next
	ch := make(chan cdpReply, 1)
	b.pending[id] = ch
	b.mu.Unlock()
	msg := map[string]any{"id": id, "method": method, "params": params}
	if session != "" {
		msg["sessionId"] = session
	}
	data, _ := json.Marshal(msg)
	if _, err := b.w.Write(append(data, 0)); err != nil {
		return err
	}
	select {
	case r := <-ch:
		if r.Error != nil {
			return errors.New(r.Error.Message)
		}
		if result != nil {
			return json.Unmarshal(r.Result, result)
		}
		return nil
	case <-time.After(15 * time.Second):
		return fmt.Errorf("%s: %w", method, errNoReply)
	}
}

type tab struct {
	b       *browser
	session string
}

func (b *browser) open(t *testing.T, url string) *tab {
	t.Helper()
	var target struct {
		TargetID string `json:"targetId"`
	}
	if err := b.call("", "Target.createTarget", map[string]any{"url": url}, &target); err != nil {
		t.Fatal(err)
	}
	var attached struct {
		SessionID string `json:"sessionId"`
	}
	if err := b.call("", "Target.attachToTarget", map[string]any{"targetId": target.TargetID, "flatten": true}, &attached); err != nil {
		t.Fatal(err)
	}
	return &tab{b, attached.SessionID}
}

// shot saves a screenshot of the tab into $NAUTILUS_SCREENSHOTS, if set,
// for looking at the popup the way users see it.
func (tb *tab) shot(t *testing.T, name string) {
	dir := os.Getenv("NAUTILUS_SCREENSHOTS")
	if dir == "" {
		return
	}
	tb.b.call(tb.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": 380, "height": 600, "deviceScaleFactor": 2, "mobile": false}, nil)
	var shot struct {
		Data []byte `json:"data"`
	}
	if err := tb.b.call(tb.session, "Page.captureScreenshot", map[string]any{"format": "png"}, &shot); err != nil {
		t.Log("screenshot:", err)
		return
	}
	os.WriteFile(filepath.Join(dir, name+".png"), shot.Data, 0o644)
}

// eval runs JavaScript in the tab and returns its value, awaiting promises.
func (tb *tab) eval(t *testing.T, expr string) any {
	t.Helper()
	var r struct {
		Result struct {
			Value any `json:"value"`
		} `json:"result"`
		ExceptionDetails *struct {
			Text      string `json:"text"`
			Exception struct {
				Description string `json:"description"`
			} `json:"exception"`
		} `json:"exceptionDetails"`
	}
	for range 50 { // the page may be reloading
		err := tb.b.call(tb.session, "Runtime.evaluate", map[string]any{"expression": expr, "awaitPromise": true, "returnByValue": true}, &r)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if r.ExceptionDetails != nil {
		t.Fatalf("%s: %s %s", expr, r.ExceptionDetails.Text, r.ExceptionDetails.Exception.Description)
	}
	return r.Result.Value
}

// waitText waits until the element's text contains want. It polls in the
// page: a stream of DevTools evaluations stalls the page's own fetches.
func (tb *tab) waitText(t *testing.T, selector, want string) {
	t.Helper()
	expr := fmt.Sprintf(`new Promise((resolve) => {
		const deadline = Date.now() + 10000;
		const check = () => {
			const text = document.querySelector(%q)?.textContent ?? "";
			if (text.includes(%q) || Date.now() > deadline) resolve(text);
			else setTimeout(check, 100);
		};
		check();
	})`, selector, want)
	var got any
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if got = tb.eval(t, expr); strings.Contains(fmt.Sprint(got), want) {
			return
		}
	}
	t.Fatalf("%s: text is %q, want %q; page: %v", selector, got, want, tb.eval(t, `document.body.innerText`))
}
