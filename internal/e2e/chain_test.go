// Package e2e runs compiled configs in real kernels, entirely on loopback.
// The hop servers are mihomo instances, so CONCH_MIHOMO is required;
// set CONCH_XRAY as well to also test xray as the client:
//
//	CONCH_MIHOMO=$(conch kernel path mihomo) CONCH_XRAY=$(conch kernel path xray) go test ./internal/e2e
package e2e

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xiongnemo/conch/internal/backend"
	"github.com/xiongnemo/conch/internal/backend/mihomo"
	"github.com/xiongnemo/conch/internal/backend/singbox"
	"github.com/xiongnemo/conch/internal/backend/xray"
	"github.com/xiongnemo/conch/internal/compile"
	"github.com/xiongnemo/conch/internal/model"
)

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// kernel is a running kernel process with its combined output captured.
type kernel struct {
	name string
	out  *syncBuffer
}

// client describes a kernel that runs conch-compiled configs.
type client struct {
	name   string
	bin    string
	router backend.Router
	file   string                          // config file name
	args   func(dir, file string) []string // command line
}

func mihomoArgs(dir, file string) []string { return []string{"-d", dir, "-f", file} }

func xrayArgs(_, file string) []string { return []string{"run", "-c", file} }

func clients() []client {
	var out []client
	if bin := os.Getenv("CONCH_MIHOMO"); bin != "" {
		out = append(out, client{"mihomo", bin, mihomo.Backend{}, "config.yaml", mihomoArgs})
	}
	if bin := os.Getenv("CONCH_XRAY"); bin != "" {
		out = append(out, client{"xray", bin, xray.Backend{}, "config.json", xrayArgs})
	}
	if bin := os.Getenv("CONCH_SING_BOX"); bin != "" {
		out = append(out, client{"sing-box", bin, singbox.Backend{}, "config.json", singBoxArgs})
	}
	return out
}

func singBoxArgs(dir, file string) []string {
	return []string{"run", "--disable-color", "-c", file, "-D", dir}
}

func hopServerBin(t *testing.T) string {
	bin := os.Getenv("CONCH_MIHOMO")
	if bin == "" {
		t.Skip("CONCH_MIHOMO not set")
	}
	return bin
}

func start(t *testing.T, name, bin, file, config string, args func(dir, file string) []string, port int) *kernel {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, file)
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	k := &kernel{name: name, out: &syncBuffer{}}
	cmd := exec.Command(bin, args(dir, path)...)
	cmd.Stdout, cmd.Stderr = k.out, k.out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			t.Logf("--- %s output ---\n%s", name, k.out)
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if err == nil {
			c.Close()
			return k
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not start listening on %d:\n%s", name, port, k.out)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// compileProfile compiles a conch profile for a backend.
func compileProfile(t *testing.T, b backend.Router, src string) string {
	t.Helper()
	p, err := model.Parse([]byte(src), "profile.yaml")
	if err != nil {
		t.Fatal(err)
	}
	res := compile.Compile(p)
	diags := append(res.Diags, backend.Check(res, b.Capabilities(), b.Name())...)
	if err := diags.Err(); err != nil {
		t.Fatal(err)
	}
	art, d := b.Encode(res, backend.Options{})
	if art == nil {
		t.Fatal(d.Err())
	}
	return string(art.Config)
}

func getVia(t *testing.T, proxyPort int, target string) string {
	t.Helper()
	proxy, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}, Timeout: 10 * time.Second}
	get := func() (string, error) {
		resp, err := client.Get(target)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		return string(body), err
	}
	// A kernel listens a moment before it handles connections (mihomo
	// closes them until its config is loaded): an answer that never came
	// is tried again for a while.
	body, err := get()
	for deadline := time.Now().Add(5 * time.Second); (err != nil || body == "") && time.Now().Before(deadline); {
		time.Sleep(100 * time.Millisecond)
		body, err = get()
	}
	if err != nil {
		t.Fatalf("GET %s via proxy: %v", target, err)
	}
	return body
}

// TestChainTraversesHopsInOrder checks, for every client kernel, that
// traffic routed to a chain enters the first hop, reaches the second hop
// through the first and only then the destination; that a group works as
// a chain's first hop, as its last hop and as the default route; and that
// other traffic bypasses the chain.
func TestChainTraversesHopsInOrder(t *testing.T) {
	hopBin := hopServerBin(t)
	for _, c := range clients() {
		t.Run(c.name, func(t *testing.T) { testChain(t, hopBin, c) })
	}
}

func testChain(t *testing.T, hopBin string, c client) {
	echo := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "echo %s", r.URL.Path)
	})}
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go echo.Serve(echoLn)
	t.Cleanup(func() { echo.Close() })
	echoPort := echoLn.Addr().(*net.TCPAddr).Port

	hop1Port, hop2Port, mixedPort := freePort(t), freePort(t), freePort(t)
	hop1 := start(t, "hop1", hopBin, "config.yaml", fmt.Sprintf(`
mode: direct
log-level: info
listeners:
  - { name: hop1-in, type: socks, listen: 127.0.0.1, port: %d, udp: true }
`, hop1Port), mihomoArgs, hop1Port)
	// The last hop resolves the test domains itself, as a real exit would.
	hop2 := start(t, "hop2", hopBin, "config.yaml", fmt.Sprintf(`
mode: direct
log-level: info
hosts:
  echo-chain.test: 127.0.0.1
  echo-group.test: 127.0.0.1
  echo-default.test: 127.0.0.1
  echo-exitgroup.test: 127.0.0.1
listeners:
  - { name: hop2-in, type: shadowsocks, listen: 127.0.0.1, port: %d, cipher: aes-128-gcm, password: test-pass, udp: true }
`, hop2Port), mihomoArgs, hop2Port)

	start(t, "client", c.bin, c.file, compileProfile(t, c.router, fmt.Sprintf(`
nodes:
  - { name: hop1, type: socks5, server: 127.0.0.1, port: %d, udp: true }
  - { name: hop2, type: ss, server: 127.0.0.1, port: %d, cipher: aes-128-gcm, password: test-pass, udp: true }
groups:
  - { name: 入口组, type: select, members: [hop1] }
  - { name: 出口组, type: select, members: [hop2] }
  - { name: 默认组, type: select, members: [测试链, DIRECT] }
chains:
  测试链: [hop1, hop2]
  组链: [入口组, hop2]
  组在后: [hop1, 出口组]
routes:
  default: 默认组
  entries:
    echo-chain.test: 测试链
    echo-group.test: 组链
    echo-exitgroup.test: 组在后
inbound: { mixed-port: %d }
`, hop1Port, hop2Port, mixedPort)), c.args, mixedPort)

	hosts := []string{"echo-chain.test", "echo-group.test", "echo-default.test", "echo-exitgroup.test"}
	for _, host := range hosts {
		if got := getVia(t, mixedPort, fmt.Sprintf("http://%s:%d/%s", host, echoPort, host)); got != "echo /"+host {
			t.Fatalf("request to %s returned %q", host, got)
		}
	}
	// 127.0.0.1 is covered by the built-in lan entry.
	if got := getVia(t, mixedPort, fmt.Sprintf("http://127.0.0.1:%d/direct", echoPort)); got != "echo /direct" {
		t.Fatalf("direct request returned %q", got)
	}

	// Each chained request is a new connection from hop1 to hop2.
	waitFor(t, "hop1 to forward every chained connection to hop2", func() bool {
		return strings.Count(hop1.out.String(), fmt.Sprintf("--> 127.0.0.1:%d", hop2Port)) >= len(hosts)
	})
	for _, host := range hosts {
		waitFor(t, "hop2 to reach "+host, func() bool {
			return strings.Contains(hop2.out.String(), fmt.Sprintf("%s:%d", host, echoPort))
		})
		if strings.Contains(hop1.out.String(), fmt.Sprintf("%s:%d", host, echoPort)) {
			t.Errorf("hop1 connected to %s itself; the chain was skipped", host)
		}
	}
	for _, k := range []*kernel{hop1, hop2} {
		if strings.Contains(k.out.String(), fmt.Sprintf("127.0.0.1:%d", echoPort)) {
			t.Errorf("direct traffic went through %s", k.name)
		}
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
