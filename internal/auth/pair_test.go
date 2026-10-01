package auth

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const ext = "chrome-extension://abcdefghijklmnop"

func TestPairing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pairings.json")
	p, err := LoadPairings(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, _, err := p.Pair("000000", "x", ext, now); err != ErrBadCode {
		t.Errorf("pairing without a code: %v", err)
	}
	code, expires := p.NewCode(now)
	if len(code) != 6 || expires.Sub(now) != codeTTL {
		t.Fatalf("code %q expires %v", code, expires)
	}
	if _, _, err := p.Pair(code, "x", "https://evil.example", now); err != ErrNotExtension {
		t.Errorf("a web page paired: %v", err)
	}
	if _, _, err := p.Pair(code, "x", ext, now.Add(codeTTL+time.Second)); err != ErrBadCode {
		t.Errorf("an expired code worked: %v", err)
	}
	pr, token, err := p.Pair(code, "Chrome", ext, now)
	if err != nil || pr.Name != "Chrome" || pr.Origin != ext {
		t.Fatalf("pair = %+v, %v", pr, err)
	}
	if _, _, err := p.Pair(code, "again", ext, now); err != ErrBadCode {
		t.Errorf("a code worked twice: %v", err)
	}
	if got, ok := p.Lookup(token); !ok || got.ID != pr.ID {
		t.Errorf("lookup = %+v, %v", got, ok)
	}
	if _, ok := p.Lookup(token + "x"); ok {
		t.Error("a wrong token was accepted")
	}

	// Pairings survive restarts, and the token is not stored.
	data, _ := os.ReadFile(path)
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("pairings.json mode %v", fi.Mode().Perm())
	}
	if len(data) == 0 || strings.Contains(string(data), token) {
		t.Errorf("pairings.json = %s", data)
	}
	again, _ := LoadPairings(path)
	if _, ok := again.Lookup(token); !ok {
		t.Error("pairing lost on reload")
	}

	// Pairing the same extension again replaces its pairing.
	code, _ = p.NewCode(now)
	_, token2, err := p.Pair(code, "Chrome", ext, now)
	if err != nil || len(p.List()) != 1 {
		t.Fatalf("re-pair: %v, %d pairings", err, len(p.List()))
	}
	if _, ok := p.Lookup(token); ok {
		t.Error("the replaced token still works")
	}
	if ok, err := p.Revoke(p.List()[0].ID); !ok || err != nil {
		t.Errorf("revoke = %v, %v", ok, err)
	}
	if _, ok := p.Lookup(token2); ok {
		t.Error("a revoked token still works")
	}
}

func TestPairCodeGuessing(t *testing.T) {
	p, _ := LoadPairings(filepath.Join(t.TempDir(), "pairings.json"))
	now := time.Now()
	code, _ := p.NewCode(now)
	wrong := "000000"
	if code == wrong {
		wrong = "000001"
	}
	for i := range codeMisses - 1 {
		if _, _, err := p.Pair(wrong, "x", ext, now); err != ErrBadCode {
			t.Fatalf("guess %d: %v", i, err)
		}
	}
	if _, _, err := p.Pair(wrong, "x", ext, now); err != ErrCodeUsedUp {
		t.Errorf("last guess: %v", err)
	}
	if _, _, err := p.Pair(code, "x", ext, now); err != ErrBadCode {
		t.Errorf("the right code after too many guesses: %v", err)
	}
}

// A paired extension may explain and change routes, nothing more, and
// only paired extensions get CORS answers.
func TestExtensionScope(t *testing.T) {
	g, h := newServer(Settings{Password: "pw", Auth: true, Listen: DefaultListen})
	g.Pairings, _ = LoadPairings(filepath.Join(t.TempDir(), "pairings.json"))
	code, _ := g.Pairings.NewCode(time.Now())
	_, token, err := g.Pairings.Pair(code, "x", ext, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	as := func(origin string) func(*http.Request) {
		return func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+token)
			r.Header.Set("Origin", origin)
		}
	}
	for _, c := range []struct {
		method, path string
		want         int
	}{
		{"GET", "/api/v1/route/explain", 299},
		{"PUT", "/api/v1/routes", 299},
		{"DELETE", "/api/v1/routes", 299},
		{"POST", "/api/v1/delay", 299},
		{"PUT", "/api/v1/mode", 403},
		{"PUT", "/api/v1/sysproxy", 403},
		{"POST", "/api/v1/pair/code", 403},
		{"GET", "/api/v1/pairings", 403},
	} {
		if got := do(h, c.method, c.path, as(ext)).Code; got != c.want {
			t.Errorf("%s %s: %d, want %d", c.method, c.path, got, c.want)
		}
	}
	// The token does not help another origin make changes.
	if got := do(h, "PUT", "/api/v1/routes", as("chrome-extension://other")).Code; got != 403 {
		t.Errorf("unpaired origin: %d", got)
	}

	preflight := do(h, "OPTIONS", "/api/v1/routes", func(r *http.Request) { r.Header.Set("Origin", ext) })
	if preflight.Code != 204 || preflight.Header().Get("Access-Control-Allow-Origin") != ext {
		t.Errorf("preflight: %d %v", preflight.Code, preflight.Header())
	}
	if got := do(h, "OPTIONS", "/api/v1/routes", func(r *http.Request) { r.Header.Set("Origin", "chrome-extension://other") }); got.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("CORS answered for an unpaired extension")
	}
	// Any extension may try to pair; web pages may not.
	if got := do(h, "OPTIONS", PairPath, func(r *http.Request) { r.Header.Set("Origin", "moz-extension://1234") }); got.Header().Get("Access-Control-Allow-Origin") != "moz-extension://1234" {
		t.Error("no CORS answer for pairing")
	}
	if got := do(h, "OPTIONS", PairPath, func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }); got.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("CORS answered a web page")
	}
}
