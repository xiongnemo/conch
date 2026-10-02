package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xiongnemo/conch/internal/daemon"
)

// TestTrojanGoSidecar runs a trojan-go server (TLS, websocket, its
// shadowsocks layer and mux) and reaches it through a daemon on each
// kernel: directly, and as the second hop of a chain, where the sidecar
// must dial through the first hop.
//
//	CONCH_TROJAN_GO=$(conch kernel path trojan-go)
func TestTrojanGoSidecar(t *testing.T) {
	tg, hopBin := os.Getenv("CONCH_TROJAN_GO"), os.Getenv("CONCH_MIHOMO")
	if tg == "" || hopBin == "" {
		t.Skip("CONCH_TROJAN_GO or CONCH_MIHOMO not set")
	}
	for _, c := range clients() {
		t.Run(c.name, func(t *testing.T) { testTrojanGo(t, tg, hopBin, c) })
	}
}

func testTrojanGo(t *testing.T, tg, hopBin string, c client) {
	// Two sites, so each can be routed on its own.
	var sites []string
	var fallback *net.TCPAddr // trojan-go servers insist on a working fallback
	for _, ip := range []string{"127.0.0.2", "127.0.0.3"} {
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })}
		ln, err := net.Listen("tcp", ip+":0")
		if err != nil {
			t.Skip("cannot listen on", ip, err)
		}
		go srv.Serve(ln)
		t.Cleanup(func() { srv.Close() })
		sites = append(sites, "http://"+ln.Addr().String()+"/")
		fallback = ln.Addr().(*net.TCPAddr)
	}

	dir := t.TempDir()
	cert, key := selfSigned(t, dir, "tg.test")
	tgPort := freePort(t)
	serverConfig := filepath.Join(dir, "server.json")
	os.WriteFile(serverConfig, []byte(fmt.Sprintf(`{
  "run_type": "server", "local_addr": "127.0.0.1", "local_port": %d,
  "remote_addr": %q, "remote_port": %d, "password": ["tg-pass"], "log_level": 1,
  "ssl": { "cert": %q, "key": %q, "sni": "tg.test" },
  "websocket": { "enabled": true, "path": "/ws", "host": "tg.test" },
  "shadowsocks": { "enabled": true, "method": "AES-128-GCM", "password": "ss-pass" },
  "mux": { "enabled": true }
}`, tgPort, fallback.IP.String(), fallback.Port, cert, key)), 0o600)
	server := start(t, "trojan-go server", tg, "server.json", "", func(string, string) []string { return []string{"-config", serverConfig} }, tgPort)

	hopPort := freePort(t)
	hop := start(t, "hop", hopBin, "config.yaml", fmt.Sprintf(`
mode: direct
log-level: info
listeners:
  - { name: in, type: socks, listen: 127.0.0.1, port: %d, udp: true }
`, hopPort), mihomoArgs, hopPort)

	mixed := freePort(t)
	profile := filepath.Join(dir, "profile.yaml")
	os.WriteFile(profile, []byte(fmt.Sprintf(`
nodes:
  - { name: hop, type: socks5, server: 127.0.0.1, port: %d, udp: true }
  - name: tg
    type: trojan-go
    server: 127.0.0.1
    port: %d
    password: tg-pass
    sni: tg.test
    skip-cert-verify: true
    network: ws
    ws-opts: { path: /ws, headers: { Host: tg.test } }
    ss-opts: { enabled: true, method: aes-128-gcm, password: ss-pass }
    mux: true
chains:
  经中转: [hop, tg]
routes:
  default: DIRECT
  entries:
    127.0.0.2: tg
    127.0.0.3: 经中转
inbound: { mixed-port: %d }
`, hopPort, tgPort, mixed)), 0o644)
	d, err := daemon.New(daemon.Options{ProfilePath: profile, DataDir: filepath.Join(dir, "data"), Backend: c.name, KernelBin: c.bin, SidecarBin: tg, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { d.Run(ctx); close(done) }()
	t.Cleanup(func() {
		cancel()
		<-done
		if t.Failed() {
			t.Logf("--- daemon log ---\n%s", strings.Join(d.Logs(), "\n"))
		}
	})
	waitFor(t, "the daemon", func() bool { return d.Status().Ready })
	if s := d.Status(); s.Error != "" {
		t.Fatal(s.Error)
	}

	for i, site := range sites {
		var got string
		for deadline := time.Now().Add(10 * time.Second); got != "ok" && time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
			got = tryGet(mixed, site) // the sidecar may still be starting
		}
		if got != "ok" {
			t.Fatalf("site %d through trojan-go returned %q", i, got)
		}
	}
	// Both sidecars reached the server (with mux it does not log targets).
	waitFor(t, "the server to accept both sidecars", func() bool {
		return strings.Count(server.out.String(), "tls connection from") >= 2
	})
	// Only the chained site's sidecar dials through the hop.
	waitFor(t, "the hop to carry the chained sidecar", func() bool {
		return strings.Contains(hop.out.String(), fmt.Sprintf("--> 127.0.0.1:%d", tgPort))
	})
	if strings.Count(hop.out.String(), fmt.Sprintf("--> 127.0.0.1:%d", tgPort)) == 0 {
		t.Error("the chain skipped its first hop")
	}
}

// selfSigned writes a certificate for host and its key into dir.
func selfSigned(t *testing.T, dir, host string) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
	return certPath, keyPath
}
