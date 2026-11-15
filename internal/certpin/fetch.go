package certpin

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/blake2b"

	"github.com/xiongnemo/conch/internal/proto"
)

// Target is where the certificates behind a pin are fetched from.
type Target struct {
	Pin        string
	Address    string // host:port
	ServerName string
	ALPN       []string
	QUIC       bool   // hysteria2
	Salamander string // hysteria2's obfs password
}

// TargetOf is where a node's pin can be checked, if it has one: REALITY
// presents no certificate of the server's own.
func TargetOf(s *proto.Spec) (Target, bool) {
	if s.TLS == nil || s.TLS.PinSHA256 == "" || s.TLS.Reality != nil {
		return Target{}, false
	}
	t := Target{
		Pin:        s.TLS.PinSHA256,
		Address:    net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		ServerName: cmp.Or(s.TLS.SNI, s.Server),
		ALPN:       s.TLS.ALPN,
	}
	if s.Type == "hysteria2" {
		t.QUIC = true
		if len(t.ALPN) == 0 {
			t.ALPN = []string{"h3"} // what Hysteria 2 servers speak
		}
		if h := s.Hysteria; h != nil && h.Obfs == "salamander" {
			t.Salamander = h.ObfsPassword
		}
	}
	return t, true
}

// Fetch completes a TLS handshake with the server, checking nothing, and
// returns the certificates it presented. Only Derive decides whether to
// believe them.
func Fetch(ctx context.Context, t Target) ([]*x509.Certificate, error) {
	conf := &tls.Config{ServerName: t.ServerName, NextProtos: t.ALPN, InsecureSkipVerify: true}
	if !t.QUIC {
		conn, err := (&tls.Dialer{Config: conf}).DialContext(ctx, "tcp", t.Address)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		return conn.(*tls.Conn).ConnectionState().PeerCertificates, nil
	}
	addr, err := net.ResolveUDPAddr("udp", t.Address)
	if err != nil {
		return nil, err
	}
	udp, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	pc := &packetConn{PacketConn: udp, psk: []byte(t.Salamander)}
	defer pc.Close()
	conn, err := quic.Dial(ctx, pc, addr, conf, &quic.Config{HandshakeIdleTimeout: 10 * time.Second})
	if err != nil {
		return nil, err
	}
	defer conn.CloseWithError(0, "")
	return conn.ConnectionState().TLS.PeerCertificates, nil
}

// Learn fetches the certificates for the pins the store does not know
// yet, trying each pin's targets in turn, and keeps what they prove.
// It reports, by pin, why the ones it could not learn failed.
func (s *Store) Learn(ctx context.Context, targets []Target) map[string]error {
	byPin := map[string][]Target{}
	var order []string
	for _, t := range targets {
		key, ok := Normalize(t.Pin)
		if !ok {
			continue // the backend says so on its own
		}
		if _, known := s.Lookup(key); known {
			continue
		}
		if byPin[key] == nil {
			order = append(order, key)
		}
		byPin[key] = append(byPin[key], t)
	}
	var (
		mu     sync.Mutex
		failed = map[string]error{}
		wg     sync.WaitGroup
		slots  = make(chan struct{}, 8)
	)
	for _, key := range order {
		wg.Go(func() {
			slots <- struct{}{}
			defer func() { <-slots }()
			var errs []error
			for i, t := range byPin[key] {
				if i == 3 || ctx.Err() != nil {
					break // nodes sharing a certificate share a server, mostly
				}
				chain, err := Fetch(ctx, t)
				if err == nil {
					var p Pin
					if p, err = Derive(chain, key); err == nil {
						err = s.Add(key, p)
					}
				}
				if err == nil {
					return
				}
				errs = append(errs, err)
			}
			mu.Lock()
			failed[key] = errors.Join(errs...)
			mu.Unlock()
		})
	}
	wg.Wait()
	return failed
}

// packetConn carries a handshake's packets, obfuscated with Hysteria 2's
// salamander when psk is set: each packet is an 8-byte salt, then the
// payload XORed with BLAKE2b-256(psk + salt).
type packetConn struct {
	net.PacketConn
	psk []byte
}

// One handshake needs no larger buffers: these keep quic-go from
// trying, and from logging that it could not.
func (c *packetConn) SetReadBuffer(int) error  { return nil }
func (c *packetConn) SetWriteBuffer(int) error { return nil }

const saltLen = 8

func (c *packetConn) key(salt []byte) [blake2b.Size256]byte {
	return blake2b.Sum256(append(append([]byte(nil), c.psk...), salt...))
}

func (c *packetConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(c.psk) == 0 {
		return c.PacketConn.WriteTo(p, addr)
	}
	out := make([]byte, saltLen+len(p))
	rand.Read(out[:saltLen])
	key := c.key(out[:saltLen])
	for i, b := range p {
		out[saltLen+i] = b ^ key[i%len(key)]
	}
	if _, err := c.PacketConn.WriteTo(out, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if len(c.psk) == 0 {
		return c.PacketConn.ReadFrom(p)
	}
	buf := make([]byte, saltLen+len(p))
	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, addr, err
		}
		if n <= saltLen {
			continue
		}
		key := c.key(buf[:saltLen])
		for i, b := range buf[saltLen:n] {
			p[i] = b ^ key[i%len(key)]
		}
		return n - saltLen, addr, nil
	}
}
