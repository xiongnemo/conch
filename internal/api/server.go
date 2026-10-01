// Package api serves the daemon's HTTP API and the embedded Web UI.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"nautilus/internal/auth"
	"nautilus/internal/daemon"
	"nautilus/internal/diag"
	"nautilus/internal/explain"
	"nautilus/internal/view"
)

// Server is the HTTP side of a daemon.
type Server struct {
	D     *daemon.Daemon
	Guard *auth.Guard
	Web   fs.FS // the Web UI; nil serves none
}

// Handler returns the API and the Web UI behind the guard.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/login", s.Guard.Login)
	mux.HandleFunc("POST /api/v1/logout", s.Guard.Logout)
	mux.HandleFunc("GET /api/v1/session", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]bool{"auth": s.Guard.Settings().Auth})
	})
	mux.HandleFunc("GET /api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.D.Status())
	})
	mux.HandleFunc("GET /api/v1/logs", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.D.Logs())
	})
	mux.HandleFunc("GET /api/v1/outbounds", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.D.Outbounds(r.Context()))
	})
	mux.HandleFunc("PUT /api/v1/groups/{name}", s.selectGroup)
	mux.HandleFunc("PUT /api/v1/chains/{name}", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Hops []string `json:"hops"`
		}
		if decode(w, r, &body) {
			s.done(w, s.D.SetChain(r.Context(), r.PathValue("name"), body.Hops))
		}
	})
	mux.HandleFunc("DELETE /api/v1/chains/{name}", func(w http.ResponseWriter, r *http.Request) {
		s.done(w, s.D.DeleteChain(r.Context(), r.PathValue("name")))
	})
	mux.HandleFunc("POST /api/v1/nodes", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Link string `json:"link"` // a share link: vmess://, vless://, ss://, trojan://, …
		}
		if !decode(w, r, &body) {
			return
		}
		name, err := s.D.AddNode(r.Context(), body.Link)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, map[string]string{"name": name})
	})
	mux.HandleFunc("DELETE /api/v1/nodes/{name}", func(w http.ResponseWriter, r *http.Request) {
		s.done(w, s.D.DeleteNode(r.Context(), r.PathValue("name")))
	})
	mux.HandleFunc("POST /api/v1/delay", s.delay)
	mux.HandleFunc("GET /api/v1/routes", s.routes)
	mux.HandleFunc("PUT /api/v1/routes", s.setRoute)
	mux.HandleFunc("DELETE /api/v1/routes", s.deleteRoute)
	mux.HandleFunc("GET /api/v1/route/explain", s.explain)
	mux.HandleFunc("PUT /api/v1/mode", s.setMode)
	mux.HandleFunc("PUT /api/v1/sysproxy", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Enabled bool `json:"enabled"`
		}
		if decode(w, r, &body) {
			s.done(w, s.D.SetSysProxy(body.Enabled))
		}
	})
	mux.HandleFunc("PUT /api/v1/tun", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Enabled bool `json:"enabled"`
		}
		if decode(w, r, &body) {
			s.done(w, s.D.SetTUN(r.Context(), body.Enabled))
		}
	})
	mux.HandleFunc("POST /api/v1/subscriptions/{name}/update", func(w http.ResponseWriter, r *http.Request) {
		s.done(w, s.D.UpdateSubscription(r.Context(), r.PathValue("name")))
	})
	mux.HandleFunc("POST /api/v1/kernel/restart", func(w http.ResponseWriter, r *http.Request) {
		s.done(w, s.D.Restart(r.Context()))
	})
	mux.HandleFunc("GET /api/v1/connections", func(w http.ResponseWriter, r *http.Request) {
		conns, err := s.D.Connections(r.Context())
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, conns)
	})
	mux.HandleFunc("DELETE /api/v1/connections/{id}", func(w http.ResponseWriter, r *http.Request) {
		s.done(w, s.D.CloseConnection(r.Context(), r.PathValue("id")))
	})
	mux.HandleFunc("GET /api/v1/failed", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.D.Failed())
	})
	mux.HandleFunc("DELETE /api/v1/failed", func(w http.ResponseWriter, r *http.Request) {
		s.D.ClearFailed()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /api/v1/suggest", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, daemon.Suggest(r.URL.Query().Get("host")))
	})
	mux.HandleFunc("GET /api/v1/events", s.events)
	mux.HandleFunc("POST "+auth.PairPath, s.pair)
	mux.HandleFunc("POST /api/v1/pair/code", s.pairCode)
	mux.HandleFunc("GET /api/v1/pairings", func(w http.ResponseWriter, r *http.Request) {
		list := []auth.Pairing{}
		if p := s.Guard.Pairings; p != nil {
			list = append(list, p.List()...)
		}
		writeJSON(w, list)
	})
	mux.HandleFunc("DELETE /api/v1/pairings/{id}", func(w http.ResponseWriter, r *http.Request) {
		if s.Guard.Pairings == nil {
			fail(w, daemon.ErrNotFound)
			return
		}
		ok, err := s.Guard.Pairings.Revoke(r.PathValue("id"))
		switch {
		case err != nil:
			fail(w, err)
		case !ok:
			fail(w, fmt.Errorf("配对 %w", daemon.ErrNotFound))
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	})
	if s.Web != nil {
		mux.Handle("GET /", http.FileServerFS(s.Web))
	}
	s.Guard.Public = func(path string) bool {
		return path == "/api/v1/login" || path == "/api/v1/session" || path == auth.PairPath || !strings.HasPrefix(path, "/api/")
	}
	return secure(s.Guard.Wrap(mux))
}

// secure adds headers that keep the UI from being framed or fed scripts
// from elsewhere.
func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) selectGroup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Selected string `json:"selected"`
	}
	if !decode(w, r, &body) {
		return
	}
	s.done(w, s.D.Select(r.Context(), r.PathValue("name"), body.Selected))
}

func (s *Server) delay(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &body) {
		return
	}
	if hops, err := s.D.ChainDelay(r.Context(), body.Name); err == nil {
		// A chain: the delay through each hop, the last being end to end.
		last := hops[len(hops)-1]
		out := map[string]any{"delay": last.Delay, "hops": hops}
		if last.Error != "" {
			out["error"] = last.Error
		}
		writeJSON(w, out)
		return
	}
	d, err := s.D.Delay(r.Context(), body.Name)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]int64{"delay": max(d.Milliseconds(), 1)})
}

func (s *Server) routes(w http.ResponseWriter, r *http.Request) {
	res := s.D.Result()
	if res == nil {
		fail(w, errors.New("配置还没有成功编译"))
		return
	}
	expires := map[string]time.Time{}
	for _, t := range s.D.Temp() {
		expires[t.Key] = t.Expires
	}
	writeJSON(w, view.TableOf(res, expires, daemon.ManagedPath(s.D.Status().Profile)))
}

func (s *Server) setRoute(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Target string `json:"target"`
		Via    string `json:"via"`
		TTL    string `json:"ttl"` // e.g. "2h"; empty for a permanent route
	}
	if !decode(w, r, &body) {
		return
	}
	var ttl time.Duration
	if body.TTL != "" {
		var err error
		if ttl, err = time.ParseDuration(body.TTL); err != nil || ttl <= 0 {
			fail(w, fmt.Errorf("ttl 应该写成 30m、2h 这样的时长"))
			return
		}
	}
	s.done(w, s.D.SetRoute(r.Context(), strings.TrimSpace(body.Target), body.Via, ttl))
}

func (s *Server) deleteRoute(w http.ResponseWriter, r *http.Request) {
	s.done(w, s.D.DeleteRoute(r.Context(), r.URL.Query().Get("target")))
}

func (s *Server) explain(w http.ResponseWriter, r *http.Request) {
	q := explain.ParseQuery(r.URL.Query().Get("target"))
	q.Process = r.URL.Query().Get("app")
	if q.Host == "" {
		fail(w, errors.New("缺少 target"))
		return
	}
	ex, err := s.D.Explain(r.Context(), q)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, view.Explain(s.D.Result(), ex))
}

// pairCode issues a code for pairing a browser extension.
func (s *Server) pairCode(w http.ResponseWriter, r *http.Request) {
	if s.Guard.Pairings == nil {
		fail(w, errors.New("这个 daemon 不支持配对浏览器扩展"))
		return
	}
	code, expires := s.Guard.Pairings.NewCode(time.Now())
	writeJSON(w, map[string]any{"code": code, "expires": expires})
}

// pair trades a pairing code for a token, for the extension asking.
func (s *Server) pair(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
		Name string `json:"name"`
	}
	if !decode(w, r, &body) {
		return
	}
	if s.Guard.Pairings == nil {
		fail(w, errors.New("这个 daemon 不支持配对浏览器扩展"))
		return
	}
	p, token, err := s.Guard.Pairings.Pair(strings.TrimSpace(body.Code), body.Name, r.Header.Get("Origin"), time.Now())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(Error{Error: err.Error()})
		return
	}
	writeJSON(w, map[string]string{"id": p.ID, "token": token})
}

func (s *Server) setMode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Mode string `json:"mode"`
	}
	if !decode(w, r, &body) {
		return
	}
	s.done(w, s.D.SetMode(r.Context(), body.Mode))
}

// events streams daemon events as Server-Sent Events.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	ch, cancel := s.D.Events.Subscribe()
	defer cancel()
	send := func(e daemon.Event) bool {
		data, err := json.Marshal(e.Data)
		if err != nil {
			return true
		}
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e.Type, data); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}
	send(daemon.Event{Type: "state", Data: s.D.Status()})
	keepalive := time.NewTicker(25 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e := <-ch:
			if !send(e) {
				return
			}
		case <-keepalive.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

func (s *Server) done(w http.ResponseWriter, err error) {
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, s.D.Status())
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		fail(w, fmt.Errorf("请求内容不是有效的 JSON：%w", err))
		return false
	}
	return true
}

// Error is the body of every failed request.
type Error struct {
	Error       string   `json:"error"`
	Where       string   `json:"where,omitempty"`
	Diagnostics []string `json:"diagnostics,omitempty"`
}

func fail(w http.ResponseWriter, err error) {
	body, code := Error{Error: err.Error()}, http.StatusBadRequest
	var userFile *daemon.ErrUserFile
	var config *daemon.ErrConfig
	switch {
	case errors.As(err, &userFile):
		code, body.Where = http.StatusConflict, userFile.Where
	case errors.As(err, &config):
		code, body.Error = http.StatusUnprocessableEntity, "配置有错误，没有生效："
		for _, d := range config.Diags {
			if d.Severity == diag.Error {
				body.Diagnostics = append(body.Diagnostics, d.String())
			}
		}
	case errors.Is(err, daemon.ErrNotFound):
		code = http.StatusNotFound
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(body)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
