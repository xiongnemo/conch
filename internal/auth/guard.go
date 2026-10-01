package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	CookieName = "nautilus_session"
	sessionTTL = 30 * 24 * time.Hour
)

// Guard checks every request to the daemon.
type Guard struct {
	mu       sync.RWMutex
	settings Settings
	key      []byte // session signing key, derived from the password

	limiter limiter
	// Origins returns extra origins allowed to make changes, such as a
	// paired browser extension.
	Origins func() []string
	// Public reports paths served without a session (the login page and
	// its assets).
	Public func(path string) bool
}

func NewGuard(s Settings) *Guard {
	g := &Guard{}
	g.Update(s)
	return g
}

// Update installs new settings, e.g. after the password changed. Sessions
// signed with the old password stop working.
func (g *Guard) Update(s Settings) {
	sum := sha256.Sum256([]byte("nautilus session v1\x00" + s.Password))
	g.mu.Lock()
	g.settings, g.key = s, sum[:]
	g.mu.Unlock()
}

func (g *Guard) Settings() Settings {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.settings
}

// Wrap applies the host, origin and authentication checks.
func (g *Guard) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := g.Settings()
		if !g.hostAllowed(r.Host, s) {
			// Defeats DNS rebinding: a hostile page cannot make the
			// browser talk to us under its own domain name.
			jsonError(w, http.StatusForbidden, "不接受这个 Host 的请求")
			return
		}
		if changes(r.Method) {
			if r.Header.Get("Origin") != "" && !g.originAllowed(r) {
				jsonError(w, http.StatusForbidden, "不接受来自其他网站的修改请求")
				return
			}
			if ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); r.ContentLength != 0 && ct != "application/json" {
				// A cross-site form can only send simple content types;
				// requiring JSON forces a CORS preflight we never grant.
				jsonError(w, http.StatusUnsupportedMediaType, "请求内容需要是 JSON")
				return
			}
		}
		public := g.Public != nil && g.Public(r.URL.Path)
		if s.Auth && !public && !g.authenticated(r) {
			jsonError(w, http.StatusUnauthorized, "需要登录")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func changes(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

func (g *Guard) hostAllowed(hostport string, s Settings) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if IsLoopback(host) {
		return true
	}
	// Listening beyond loopback (with authentication) allows addresses,
	// never names, so the LAN can connect but rebinding cannot.
	listenHost, _, _ := net.SplitHostPort(s.Listen)
	return !IsLoopback(listenHost) && net.ParseIP(host) != nil
}

func (g *Guard) originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if u, err := url.Parse(origin); err == nil && u.Host == r.Host {
		return true
	}
	if g.Origins != nil {
		for _, o := range g.Origins() {
			if o == origin {
				return true
			}
		}
	}
	return false
}

func (g *Guard) authenticated(r *http.Request) bool {
	if token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		return g.passwordOK(token)
	}
	c, err := r.Cookie(CookieName)
	return err == nil && g.sessionOK(c.Value, time.Now())
}

func (g *Guard) passwordOK(p string) bool {
	s := g.Settings()
	a, b := sha256.Sum256([]byte(p)), sha256.Sum256([]byte(s.Password))
	return s.Password != "" && subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// session values are "<expiry unix>.<hmac>": stateless, so restarts keep
// users logged in, and a new password invalidates every session.
func (g *Guard) sign(payload string) string {
	g.mu.RLock()
	mac := hmac.New(sha256.New, g.key)
	g.mu.RUnlock()
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (g *Guard) issue(now time.Time) string {
	payload := strconv.FormatInt(now.Add(sessionTTL).Unix(), 10)
	return payload + "." + g.sign(payload)
}

func (g *Guard) sessionOK(v string, now time.Time) bool {
	payload, sig, ok := strings.Cut(v, ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(g.sign(payload))) {
		return false
	}
	exp, err := strconv.ParseInt(payload, 10, 64)
	return err == nil && now.Unix() < exp
}

// Login handles POST {"password": "…"}.
func (g *Guard) Login(w http.ResponseWriter, r *http.Request) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if wait := g.limiter.wait(ip, time.Now()); wait > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		jsonError(w, http.StatusTooManyRequests, "尝试次数太多，请 "+wait.Round(time.Second).String()+" 后再试")
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil || !g.passwordOK(body.Password) {
		g.limiter.fail(ip, time.Now())
		jsonError(w, http.StatusUnauthorized, "密码不对")
		return
	}
	g.limiter.reset(ip)
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: g.issue(time.Now()), Path: "/",
		MaxAge: int(sessionTTL.Seconds()), HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (g *Guard) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

func jsonError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// limiter slows down password guessing per client address: after five
// failures each attempt waits twice as long, up to fifteen minutes.
type limiter struct {
	mu    sync.Mutex
	fails map[string]*attempts
}

type attempts struct {
	n    int
	last time.Time
}

func (l *limiter) wait(ip string, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.fails[ip]
	if a == nil || a.n < 5 {
		return 0
	}
	delay := min(time.Second<<(a.n-5), 15*time.Minute)
	return max(0, a.last.Add(delay).Sub(now))
}

func (l *limiter) fail(ip string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fails == nil {
		l.fails = map[string]*attempts{}
	}
	a := l.fails[ip]
	if a == nil || now.Sub(a.last) > time.Hour {
		a = &attempts{}
		l.fails[ip] = a
	}
	a.n++
	a.last = now
}

func (l *limiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, ip)
}
