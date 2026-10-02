package auth

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// private reports whether only the owner can read the file. Windows has no
// Unix permission bits (Go reports 0666 for every writable file), so the
// check only applies elsewhere.
func private(fi os.FileInfo) bool {
	return runtime.GOOS == "windows" || fi.Mode().Perm() == 0o600
}

func TestLoadPrecedence(t *testing.T) {
	cwd, cfg := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(cfg, ".env"), []byte("CONCH_PASSWORD=from-config\nCONCH_LISTEN=127.0.0.1:1111\n"), 0o600)
	os.WriteFile(filepath.Join(cwd, ".env"), []byte("# comment\nexport CONCH_PASSWORD=\"from-cwd\"\n"), 0o600)
	s, err := Load(cwd, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.Password != "from-cwd" || s.Listen != "127.0.0.1:1111" || !s.Auth || s.PasswordFile != filepath.Join(cwd, ".env") {
		t.Errorf("settings = %+v (./.env wins per key, config dir fills the rest)", s)
	}
	t.Setenv("CONCH_PASSWORD", "from-env")
	if s, _ := Load(cwd, cfg); s.Password != "from-env" {
		t.Errorf("the environment must win, got %q", s.Password)
	}
}

func TestAuthOffOnlyOnLoopback(t *testing.T) {
	cwd := t.TempDir()
	os.WriteFile(filepath.Join(cwd, ".env"), []byte("CONCH_AUTH=off\nCONCH_LISTEN=0.0.0.0:9277\n"), 0o600)
	if _, err := Load(cwd, t.TempDir()); err == nil {
		t.Error("an unauthenticated API must not listen beyond loopback")
	}
}

func TestEnsureAndSetPassword(t *testing.T) {
	cwd, cfg := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(cwd, ".env"), []byte("OTHER=1"), 0o600)
	s := Settings{Auth: true, Listen: DefaultListen}
	file, err := Ensure(&s, cwd, cfg)
	if err != nil || file != filepath.Join(cwd, ".env") || len(s.Password) < 20 {
		t.Fatalf("Ensure = %q, %v, password %q", file, err, s.Password)
	}
	st, _ := os.Stat(file)
	data, _ := os.ReadFile(file)
	if !private(st) || !strings.Contains(string(data), "OTHER=1\nCONCH_PASSWORD="+s.Password) {
		t.Errorf("file mode %v, content %q", st.Mode().Perm(), data)
	}
	if err := SetPassword(file, "new"); err != nil {
		t.Fatal(err)
	}
	if got, _ := Load(cwd, cfg); got.Password != "new" {
		t.Errorf("after SetPassword the password is %q", got.Password)
	}
	data, _ = os.ReadFile(file)
	if strings.Count(string(data), "CONCH_PASSWORD") != 1 || !strings.Contains(string(data), "OTHER=1") {
		t.Errorf("SetPassword must replace the line and keep the others: %q", data)
	}
}

func newServer(s Settings) (*Guard, http.Handler) {
	g := NewGuard(s)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", g.Login)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(299) })
	g.Public = func(p string) bool { return p == "/api/login" }
	return g, g.Wrap(mux)
}

func do(h http.Handler, method, path string, mod func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://127.0.0.1:9277"+path, strings.NewReader(`{"password":"pw"}`))
	r.Header.Set("Content-Type", "application/json")
	if mod != nil {
		mod(r)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestGuard(t *testing.T) {
	g, h := newServer(Settings{Password: "pw", Auth: true, Listen: DefaultListen})
	if code := do(h, "GET", "/api/status", nil).Code; code != 401 {
		t.Errorf("unauthenticated request: %d, want 401", code)
	}
	if code := do(h, "GET", "/api/status", func(r *http.Request) { r.Header.Set("Authorization", "Bearer pw") }).Code; code != 299 {
		t.Errorf("bearer password: %d", code)
	}
	login := do(h, "POST", "/api/login", nil)
	cookies := login.Result().Cookies()
	if login.Code != 204 || len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("login: %d %+v", login.Code, cookies)
	}
	withCookie := func(r *http.Request) { r.AddCookie(cookies[0]) }
	if code := do(h, "GET", "/api/status", withCookie).Code; code != 299 {
		t.Errorf("session cookie: %d", code)
	}
	tampered := func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: CookieName, Value: "9999999999." + strings.Repeat("A", 43)})
	}
	if code := do(h, "GET", "/api/status", tampered).Code; code != 401 {
		t.Errorf("forged session accepted: %d", code)
	}
	if g.sessionOK(g.issue(time.Now().Add(-31*24*time.Hour)), time.Now()) {
		t.Error("an expired session must be rejected")
	}
	g.Update(Settings{Password: "changed", Auth: true, Listen: DefaultListen})
	if code := do(h, "GET", "/api/status", withCookie).Code; code != 401 {
		t.Errorf("a new password must end old sessions: %d", code)
	}
}

func TestGuardChecksWithoutAuth(t *testing.T) {
	_, h := newServer(Settings{Auth: false, Listen: DefaultListen})
	tests := []struct {
		name string
		mod  func(*http.Request)
		want int
	}{
		{"plain local request", nil, 299},
		{"DNS rebinding host", func(r *http.Request) { r.Host = "evil.example:9277" }, 403},
		{"cross-site origin", func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }, 403},
		{"opaque origin", func(r *http.Request) { r.Header.Set("Origin", "null") }, 403},
		{"same origin", func(r *http.Request) { r.Header.Set("Origin", "http://127.0.0.1:9277") }, 299},
		{"form post", func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, 415},
	}
	for _, tt := range tests {
		if got := do(h, "PUT", "/api/mode", tt.mod).Code; got != tt.want {
			t.Errorf("%s: %d, want %d", tt.name, got, tt.want)
		}
	}
}

func TestLoginRateLimit(t *testing.T) {
	_, h := newServer(Settings{Password: "right", Auth: true, Listen: DefaultListen})
	for i := range 5 {
		if code := do(h, "POST", "/api/login", nil).Code; code != 401 {
			t.Fatalf("attempt %d: %d", i, code)
		}
	}
	if code := do(h, "POST", "/api/login", nil).Code; code != 429 {
		t.Errorf("sixth wrong password in a row: %d, want 429", code)
	}
}

// Without a password no session is valid: not even one signed with the
// key an empty password would give.
func TestNoPasswordNoSessions(t *testing.T) {
	g := NewGuard(Settings{Auth: true, Listen: DefaultListen})
	forger := &Guard{}
	sum := sha256.Sum256([]byte("conch session v1\x00"))
	forger.key = sum[:]
	cookie := forger.sign(fmt.Sprint(time.Now().Add(time.Hour).Unix()))
	if g.sessionOK(cookie, time.Now()) {
		t.Error("a session forged for an empty password was accepted")
	}
	if g.passwordOK("") {
		t.Error("an empty password was accepted")
	}
}

// Failures keep being slowed down however many there were.
func TestLimiterKeepsLimiting(t *testing.T) {
	var l limiter
	now := time.Now()
	for range 100 {
		l.fail("192.0.2.1", now)
	}
	if w := l.wait("192.0.2.1", now); w <= 0 || w > 15*time.Minute {
		t.Errorf("wait after 100 failures = %v", w)
	}
}
