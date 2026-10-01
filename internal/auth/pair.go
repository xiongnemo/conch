package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// Pairings lets browser extensions use part of the API with a token of
// their own. The user pairs an extension by typing a short code that
// `nautilus pair` or the Web UI shows; the code works once, for two
// minutes, and five wrong guesses use it up.
type Pairings struct {
	path string

	mu   sync.Mutex
	list []Pairing
	code *pairCode
}

// Pairing is one paired extension.
type Pairing struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Origin  string    `json:"origin,omitempty"` // e.g. chrome-extension://abc…
	Hash    string    `json:"tokenSHA256"`
	Created time.Time `json:"created"`
}

type pairCode struct {
	code    string
	expires time.Time
	misses  int
}

const (
	codeTTL    = 2 * time.Minute
	codeMisses = 5
)

var (
	ErrBadCode      = errors.New("配对码不对或已经过期，请重新获取")
	ErrCodeUsedUp   = errors.New("配对码输错的次数太多，已经作废，请重新获取")
	ErrNotExtension = errors.New("只有浏览器扩展可以配对")
)

// LoadPairings reads the pairings kept in path, which need not exist yet.
func LoadPairings(path string) (*Pairings, error) {
	p := &Pairings{path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &p.list); err != nil {
		return nil, fmt.Errorf("读取 %s：%w", path, err)
	}
	return p, nil
}

func (p *Pairings) saveLocked() error {
	data, err := json.MarshalIndent(p.list, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p.path), 0o700); err != nil {
		return err
	}
	return writePrivate(p.path, append(data, '\n'))
}

// NewCode issues a pairing code, replacing any earlier one.
func (p *Pairings) NewCode(now time.Time) (string, time.Time) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		panic(err) // crypto/rand does not fail
	}
	c := &pairCode{code: fmt.Sprintf("%06d", n.Int64()), expires: now.Add(codeTTL)}
	p.mu.Lock()
	p.code = c
	p.mu.Unlock()
	return c.code, c.expires
}

// Pair trades a code for a token. Pairing the same origin again replaces
// its earlier pairing.
func (p *Pairings) Pair(code, name, origin string, now time.Time) (Pairing, string, error) {
	if origin != "" && !IsExtensionOrigin(origin) {
		return Pairing{}, "", ErrNotExtension
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	c := p.code
	if c == nil || now.After(c.expires) {
		return Pairing{}, "", ErrBadCode
	}
	if subtle.ConstantTimeCompare([]byte(code), []byte(c.code)) != 1 {
		if c.misses++; c.misses >= codeMisses {
			p.code = nil
			return Pairing{}, "", ErrCodeUsedUp
		}
		return Pairing{}, "", ErrBadCode
	}
	p.code = nil
	token := "np_" + randomString(32)
	pr := Pairing{ID: randomString(6), Name: strings.TrimSpace(name), Origin: origin, Hash: tokenHash(token), Created: now.UTC().Truncate(time.Second)}
	if pr.Name == "" {
		pr.Name = "浏览器扩展"
	}
	kept := slices.DeleteFunc(slices.Clone(p.list), func(old Pairing) bool { return origin != "" && old.Origin == origin })
	old := p.list
	p.list = append(kept, pr)
	if err := p.saveLocked(); err != nil {
		p.list = old
		return Pairing{}, "", err
	}
	return pr, token, nil
}

// Lookup returns the pairing a token belongs to.
func (p *Pairings) Lookup(token string) (Pairing, bool) {
	if !strings.HasPrefix(token, "np_") {
		return Pairing{}, false
	}
	h := tokenHash(token)
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, pr := range p.list {
		if subtle.ConstantTimeCompare([]byte(pr.Hash), []byte(h)) == 1 {
			return pr, true
		}
	}
	return Pairing{}, false
}

// Origins lists the paired extensions' origins.
func (p *Pairings) Origins() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for _, pr := range p.list {
		if pr.Origin != "" {
			out = append(out, pr.Origin)
		}
	}
	return out
}

func (p *Pairings) List() []Pairing {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.list)
}

// Revoke forgets a pairing; its token stops working at once.
func (p *Pairings) Revoke(id string) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := len(p.list)
	p.list = slices.DeleteFunc(p.list, func(pr Pairing) bool { return pr.ID == id })
	if len(p.list) == n {
		return false, nil
	}
	return true, p.saveLocked()
}

// IsExtensionOrigin reports whether origin belongs to a browser extension.
func IsExtensionOrigin(origin string) bool {
	for _, scheme := range []string{"chrome-extension://", "moz-extension://", "safari-web-extension://"} {
		if rest, ok := strings.CutPrefix(origin, scheme); ok && rest != "" && !strings.ContainsAny(rest, "/?#") {
			return true
		}
	}
	return false
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func randomString(n int) string {
	buf := make([]byte, n)
	rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// extensionScope is what a paired extension may do: explain and change
// routes, and read what it needs for that. It cannot switch modes or the
// system proxy, restart the kernel, or pair other extensions.
var extensionScope = map[string]bool{
	"GET /api/v1/status":        true,
	"GET /api/v1/routes":        true,
	"PUT /api/v1/routes":        true,
	"DELETE /api/v1/routes":     true,
	"GET /api/v1/route/explain": true,
	"GET /api/v1/outbounds":     true,
	"GET /api/v1/suggest":       true,
	"GET /api/v1/failed":        true,
	"POST /api/v1/delay":        true,
}

func inExtensionScope(r *http.Request) bool { return extensionScope[r.Method+" "+r.URL.Path] }
