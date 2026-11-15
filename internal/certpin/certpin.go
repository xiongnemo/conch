// Package certpin translates a certificate pin, the SHA-256 of a
// certificate in the server's chain, for kernels that cannot check one.
//
// mihomo and xray check such a pin as written: a pinned leaf is accepted
// as it is, a pinned CA becomes the only root the chain is verified to
// (with the server name). sing-box can pin only a leaf's public key, or
// trust given roots. Both say the same thing as the pin, but need the
// certificate itself: conch fetches the server's chain, keeps it only
// when a certificate in it has the pinned hash, and remembers what it
// derived by that hash. The result is a function of the certificate
// alone, so it never goes stale.
package certpin

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Pin is a certificate pin in the forms other kernels take.
type Pin struct {
	// PublicKeySHA256 is the base64 SHA-256 of the pinned leaf
	// certificate's public key (its SubjectPublicKeyInfo).
	PublicKeySHA256 string `json:"publicKeySha256,omitempty"`
	// Leaf is the pinned leaf certificate, in PEM, for kernels that can
	// only trust roots.
	Leaf string `json:"leaf,omitempty"`
	// CA is the pinned certificate, in PEM, when it is a CA of the chain
	// rather than the server's own: the chain is verified to it alone.
	CA string `json:"ca,omitempty"`
}

// Lookup finds what a pin, as written in a profile, was learned to be.
type Lookup func(pin string) (Pin, bool)

// Normalize writes a pin the one way it is stored: lowercase hex without
// separators. It reports false for what is not a SHA-256.
func Normalize(pin string) (string, bool) {
	pin = strings.ToLower(strings.NewReplacer(":", "", " ", "", "-", "").Replace(strings.TrimSpace(pin)))
	if b, err := hex.DecodeString(pin); err != nil || len(b) != sha256.Size {
		return "", false
	}
	return pin, true
}

// ErrNotInChain is a server whose certificates have none with the pinned
// hash: the pin is wrong, or someone is in the way.
var ErrNotInChain = errors.New("服务器的证书和指纹对不上")

// Derive finds the pinned certificate in a server's chain, leaf first,
// the way mihomo and xray look for it.
func Derive(chain []*x509.Certificate, pin string) (Pin, error) {
	want, ok := Normalize(pin)
	if !ok {
		return Pin{}, fmt.Errorf("指纹 %q 不是 SHA-256", pin)
	}
	for i, c := range chain {
		sum := sha256.Sum256(c.Raw)
		if hex.EncodeToString(sum[:]) != want {
			continue
		}
		if i == 0 {
			spki := sha256.Sum256(c.RawSubjectPublicKeyInfo)
			return Pin{PublicKeySHA256: base64.StdEncoding.EncodeToString(spki[:]), Leaf: pemOf(c)}, nil
		}
		if !c.IsCA {
			continue // xray only takes CAs past the leaf
		}
		return Pin{CA: pemOf(c)}, nil
	}
	return Pin{}, ErrNotInChain
}

func pemOf(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

// Store keeps learned pins in a file.
type Store struct {
	path string
	mu   sync.Mutex
	pins map[string]Pin
}

// Open reads the pins learned before; a missing or damaged file is an
// empty store, since everything in it can be learned again.
func Open(path string) *Store {
	s := &Store{path: path, pins: map[string]Pin{}}
	if b, err := os.ReadFile(path); err == nil {
		json.Unmarshal(b, &s.pins)
	}
	return s
}

func (s *Store) Lookup(pin string) (Pin, bool) {
	key, ok := Normalize(pin)
	if !ok {
		return Pin{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pins[key]
	return p, ok
}

// Add remembers what a pin is and saves the store.
func (s *Store) Add(pin string, p Pin) error {
	key, ok := Normalize(pin)
	if !ok {
		return fmt.Errorf("指纹 %q 不是 SHA-256", pin)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pins[key] = p
	b, err := json.MarshalIndent(s.pins, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
