// Package e2e runs compiled configs in real kernels. The tests need a
// mihomo binary: NAUTILUS_MIHOMO=$(nautilus kernel path) go test ./internal/e2e
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

	"nautilus/internal/backend"
	"nautilus/internal/backend/mihomo"
	"nautilus/internal/compile"
	"nautilus/internal/model"
)

func mihomoBin(t *testing.T) string {
	bin := os.Getenv("NAUTILUS_MIHOMO")
	if bin == "" {
		t.Skip("NAUTILUS_MIHOMO not set")
	}
	return bin
}

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

// kernel is a running mihomo process with its combined output captured.
type kernel struct {
	name string
	out  *syncBuffer
}

func startKernel(t *testing.T, bin, name, config string, port int) *kernel {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	k := &kernel{name: name, out: &syncBuffer{}}
	cmd := exec.Command(bin, "-d", dir, "-f", path)
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

// compileProfile compiles a nautilus profile into a mihomo config.
func compileProfile(t *testing.T, src string) string {
	t.Helper()
	p, err := model.Parse([]byte(src), "profile.yaml")
	if err != nil {
		t.Fatal(err)
	}
	res := compile.Compile(p)
	if err := res.Diags.Err(); err != nil {
		t.Fatal(err)
	}
	art, err := mihomo.Backend{}.Encode(res, backend.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return string(art.Config)
}

func getVia(t *testing.T, proxyPort int, target string) string {
	t.Helper()
	proxy, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}, Timeout: 10 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		t.Fatalf("GET %s via proxy: %v", target, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

// TestChainTraversesHopsInOrder checks that traffic routed to a chain
// enters the first hop, reaches the second hop through the first, and only
// then reaches the destination; and that other traffic bypasses the chain.
func TestChainTraversesHopsInOrder(t *testing.T) {
	bin := mihomoBin(t)

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
	hop1 := startKernel(t, bin, "hop1", fmt.Sprintf(`
mode: direct
log-level: info
listeners:
  - { name: hop1-in, type: socks, listen: 127.0.0.1, port: %d, udp: true }
`, hop1Port), hop1Port)
	// The last hop resolves the test domain itself, as a real exit would.
	hop2 := startKernel(t, bin, "hop2", fmt.Sprintf(`
mode: direct
log-level: info
hosts:
  echo-chain.test: 127.0.0.1
listeners:
  - { name: hop2-in, type: shadowsocks, listen: 127.0.0.1, port: %d, cipher: aes-128-gcm, password: test-pass, udp: true }
`, hop2Port), hop2Port)

	client := startKernel(t, bin, "client", compileProfile(t, fmt.Sprintf(`
nodes:
  - { name: hop1, type: socks5, server: 127.0.0.1, port: %d, udp: true }
  - { name: hop2, type: ss, server: 127.0.0.1, port: %d, cipher: aes-128-gcm, password: test-pass, udp: true }
chains:
  测试链: [hop1, hop2]
routes:
  default: DIRECT
  entries:
    echo-chain.test: 测试链
inbound: { mixed-port: %d }
`, hop1Port, hop2Port, mixedPort)), mixedPort)

	if got := getVia(t, mixedPort, fmt.Sprintf("http://echo-chain.test:%d/chain", echoPort)); got != "echo /chain" {
		t.Fatalf("chained request returned %q", got)
	}
	// Direct traffic (127.0.0.1 is covered by the built-in lan entry).
	if got := getVia(t, mixedPort, fmt.Sprintf("http://127.0.0.1:%d/direct", echoPort)); got != "echo /direct" {
		t.Fatalf("direct request returned %q", got)
	}

	waitFor(t, "hop1 to forward to hop2", func() bool {
		return strings.Contains(hop1.out.String(), fmt.Sprintf("127.0.0.1:%d", hop2Port))
	})
	waitFor(t, "hop2 to reach the destination", func() bool {
		return strings.Contains(hop2.out.String(), fmt.Sprintf("echo-chain.test:%d", echoPort))
	})
	if strings.Contains(hop1.out.String(), fmt.Sprintf("echo-chain.test:%d", echoPort)) {
		t.Error("hop1 connected to the destination itself; the chain was skipped")
	}
	for _, k := range []*kernel{hop1, hop2} {
		if strings.Contains(k.out.String(), "/direct") || strings.Contains(k.out.String(), fmt.Sprintf("127.0.0.1:%d", echoPort)) {
			t.Errorf("direct traffic went through %s", k.name)
		}
	}
	if !strings.Contains(client.out.String(), "测试链") {
		t.Error("client log does not mention the chain")
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
