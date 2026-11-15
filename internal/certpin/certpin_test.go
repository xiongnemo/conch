package certpin

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/xiongnemo/conch/internal/proto"
)

// chain makes a CA, an intermediate that is not a CA (as some broken
// servers send), and a leaf for 127.0.0.1 signed by the CA.
type chain struct {
	ca, notCA, leaf *x509.Certificate
	leafKey         *ecdsa.PrivateKey
}

func newChain(t *testing.T) chain {
	t.Helper()
	key := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	make := func(tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	now := time.Now()
	caKey, otherKey, leafKey := key(), key(), key()
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "conch test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	ca := make(caTmpl, caTmpl, &caKey.PublicKey, caKey)
	notCATmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "not a CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	notCA := make(notCATmpl, ca, &otherKey.PublicKey, caKey)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "server"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	leaf := make(leafTmpl, ca, &leafKey.PublicKey, caKey)
	return chain{ca, notCA, leaf, leafKey}
}

func hash(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// colons writes a pin the way certificate tools print it.
func colons(h string) string {
	var parts []string
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, strings.ToUpper(h[i:i+2]))
	}
	return strings.Join(parts, ":")
}

func TestDerive(t *testing.T) {
	c := newChain(t)
	certs := []*x509.Certificate{c.leaf, c.notCA, c.ca}
	spki := sha256.Sum256(c.leaf.RawSubjectPublicKeyInfo)

	p, err := Derive(certs, colons(hash(c.leaf)))
	if err != nil || p.PublicKeySHA256 != base64.StdEncoding.EncodeToString(spki[:]) || p.CA != "" {
		t.Errorf("leaf: %+v, %v", p, err)
	}
	p, err = Derive(certs, strings.ToUpper(hash(c.ca)))
	if block, _ := pem.Decode([]byte(p.CA)); err != nil || block == nil || string(block.Bytes) != string(c.ca.Raw) || p.PublicKeySHA256 != "" {
		t.Errorf("CA: %+v, %v", p, err)
	}
	// Past the leaf only a CA is taken, as xray does.
	if _, err := Derive(certs, hash(c.notCA)); !errors.Is(err, ErrNotInChain) {
		t.Errorf("not a CA: %v", err)
	}
	if _, err := Derive(certs, strings.Repeat("ab", 32)); !errors.Is(err, ErrNotInChain) {
		t.Errorf("unknown: %v", err)
	}
	if _, err := Derive(certs, "chrome"); err == nil || errors.Is(err, ErrNotInChain) {
		t.Errorf("not a SHA-256: %v", err)
	}
}

func TestStoreKeepsPins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "certs.json")
	pin := strings.Repeat("AB", 32)
	if err := Open(path).Add(pin, Pin{PublicKeySHA256: "k"}); err != nil {
		t.Fatal(err)
	}
	if p, ok := Open(path).Lookup(colons(strings.Repeat("ab", 32))); !ok || p.PublicKeySHA256 != "k" {
		t.Errorf("after reopening: %+v, %v", p, ok)
	}
}

func TestLearnOverTCP(t *testing.T) {
	c := newChain(t)
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{c.leaf.Raw, c.ca.Raw}, PrivateKey: c.leafKey}}}
	srv.StartTLS()
	defer srv.Close()
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	n := &proto.Spec{Type: "trojan", Server: host, Port: atoi(port), TLS: &proto.TLS{PinSHA256: hash(c.ca), Insecure: true}}
	target, ok := TargetOf(n)
	if !ok {
		t.Fatal("no target for a pinned node")
	}
	s := Open(filepath.Join(t.TempDir(), "certs.json"))
	if failed := s.Learn(context.Background(), []Target{target}); len(failed) > 0 {
		t.Fatal(failed)
	}
	if p, ok := s.Lookup(hash(c.ca)); !ok || p.CA == "" {
		t.Errorf("CA pin not learned: %+v", p)
	}
	// A pin the server's chain does not have is not learned.
	target.Pin = strings.Repeat("ab", 32)
	if failed := s.Learn(context.Background(), []Target{target}); !errors.Is(failed[target.Pin], ErrNotInChain) {
		t.Errorf("wrong pin: %v", failed)
	}
	if _, ok := s.Lookup(target.Pin); ok {
		t.Error("a wrong pin was learned")
	}
}

func TestNoTargetForREALITY(t *testing.T) {
	n := &proto.Spec{Type: "vless", Server: "a.example", Port: 443, TLS: &proto.TLS{PinSHA256: strings.Repeat("ab", 32), Reality: &proto.Reality{PublicKey: "k"}}}
	if _, ok := TargetOf(n); ok {
		t.Error("REALITY has no certificate of the server's own to pin")
	}
}

// quicServer answers QUIC handshakes with the leaf, behind salamander
// when psk is set.
func quicServer(t *testing.T, c chain, psk string) string {
	t.Helper()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	pc := &packetConn{PacketConn: udp, psk: []byte(psk)}
	conf := &tls.Config{NextProtos: []string{"h3"}, Certificates: []tls.Certificate{{Certificate: [][]byte{c.leaf.Raw}, PrivateKey: c.leafKey}}}
	ln, err := quic.Listen(pc, conf, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close(); pc.Close() })
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func() { time.Sleep(time.Second); conn.CloseWithError(0, "") }()
		}
	}()
	return udp.LocalAddr().String()
}

func TestFetchOverQUIC(t *testing.T) {
	c := newChain(t)
	for _, psk := range []string{"", "obfs-password"} {
		addr := quicServer(t, c, psk)
		host, port, _ := net.SplitHostPort(addr)
		n := &proto.Spec{Type: "hysteria2", Server: host, Port: atoi(port), Password: "p", TLS: &proto.TLS{PinSHA256: hash(c.leaf)}, Hysteria: &proto.Hysteria{}}
		if psk != "" {
			n.Hysteria.Obfs, n.Hysteria.ObfsPassword = "salamander", psk
		}
		target, _ := TargetOf(n)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		certs, err := Fetch(ctx, target)
		cancel()
		if err != nil || len(certs) == 0 || hash(certs[0]) != hash(c.leaf) {
			t.Errorf("salamander %q: %v", psk, err)
		}
	}
}

func atoi(s string) int {
	n := 0
	for _, r := range s {
		n = n*10 + int(r-'0')
	}
	return n
}

// TestFetchFromHysteria2 fetches from a real Hysteria 2 server behind
// salamander, sing-box's:
//
//	CONCH_SING_BOX=$(conch kernel path sing-box)
func TestFetchFromHysteria2(t *testing.T) {
	bin := os.Getenv("CONCH_SING_BOX")
	if bin == "" {
		t.Skip("CONCH_SING_BOX not set")
	}
	c := newChain(t)
	dir := t.TempDir()
	keyDER, err := x509.MarshalECPrivateKey(c.leafKey)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.leaf.Raw}), 0o600)
	os.WriteFile(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
	free, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := free.LocalAddr().(*net.UDPAddr).Port
	free.Close()
	config := fmt.Sprintf(`{"log": {"level": "error"},
  "inbounds": [{"type": "hysteria2", "listen": "127.0.0.1", "listen_port": %d, "obfs": {"type": "salamander", "password": "obfs-password"},
    "users": [{"password": "p"}], "tls": {"enabled": true, "alpn": ["h3"], "certificate_path": %q, "key_path": %q}}],
  "outbounds": [{"type": "direct"}]}`, port, filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	os.WriteFile(filepath.Join(dir, "server.json"), []byte(config), 0o600)
	cmd := exec.Command(bin, "run", "--disable-color", "-c", filepath.Join(dir, "server.json"), "-D", dir)
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })

	n := &proto.Spec{Type: "hysteria2", Server: "127.0.0.1", Port: port, Password: "p", TLS: &proto.TLS{PinSHA256: hash(c.leaf)},
		Hysteria: &proto.Hysteria{Obfs: "salamander", ObfsPassword: "obfs-password"}}
	target, _ := TargetOf(n)
	deadline := time.Now().Add(10 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		certs, err := Fetch(ctx, target)
		cancel()
		if err == nil && len(certs) > 0 && hash(certs[0]) == hash(c.leaf) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no certificate from sing-box's hysteria2: %v\n%s", err, out.String())
		}
		time.Sleep(200 * time.Millisecond)
	}
}
