package daemon

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"

	"nautilus/internal/compile"
	"nautilus/internal/control"
	"nautilus/internal/view"
)

// Connection is an open connection explained in the user's terms.
type Connection struct {
	control.Connection
	Matched string   `json:"matched"` // the entry or list that routed it
	Via     []string `json:"via"`     // outbounds from the rule's target down to the node
}

// Connections lists open connections with the rule that routed each.
func (d *Daemon) Connections(ctx context.Context) ([]Connection, error) {
	conns, err := d.ctl.Connections(ctx)
	if errors.Is(err, control.ErrUnsupported) {
		return nil, fmt.Errorf("%s 内核不提供连接列表", d.backend.Name())
	}
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	res, art := d.res, d.art
	d.mu.Unlock()
	rules := map[string]string{}
	if res != nil && art != nil {
		for _, mr := range art.Manifest.Rules {
			if mr.Index >= len(res.Rules) {
				continue
			}
			fields := strings.Split(mr.Rule, ",")
			payload := ""
			if len(fields) > 2 {
				payload = fields[1]
			}
			rules[ruleKey(fields[0], payload)] = view.Rule(res.Rules[mr.Index])
		}
	}
	out := make([]Connection, 0, len(conns))
	for _, c := range conns {
		via := slices.Clone(c.Chains)
		slices.Reverse(via)
		for i, name := range via {
			via[i] = hopName(res, name)
		}
		out = append(out, Connection{Connection: c, Matched: cmpOr(rules[ruleKey(c.Rule, c.RulePayload)], c.Rule+" "+c.RulePayload), Via: via})
	}
	slices.SortFunc(out, func(a, b Connection) int { return b.Start.Compare(a.Start) })
	return out, nil
}

// ruleKey compares a kernel's rule type with an emitted rule line:
// "DomainSuffix" and "DOMAIN-SUFFIX" are the same type.
func ruleKey(typ, payload string) string {
	return strings.ToLower(strings.ReplaceAll(typ, "-", "")) + "," + payload
}

// hopName shows a chain's internal hop clone as the node and chain it is.
func hopName(res *compile.Result, name string) string {
	if res == nil {
		return name
	}
	for _, p := range res.Proxies {
		if p.Name == name && p.Kind == compile.ProxyChainHop {
			return fmt.Sprintf("%s（链 %s 第 %d 跳）", p.Node.Name, p.Chain, p.Hop+1)
		}
	}
	return name
}

func (d *Daemon) CloseConnection(ctx context.Context, id string) error {
	return d.ctl.CloseConnection(ctx, id)
}

// Failed is a destination connections to it have recently failed for.
type Failed struct {
	Host  string    `json:"host"`
	Port  string    `json:"port"`
	Via   string    `json:"via"` // the outbound that failed
	Count int       `json:"count"`
	Error string    `json:"error"`
	Last  time.Time `json:"last"`
}

// failures collects dial errors from the kernel's log, so users can see
// which sites do not load and route them elsewhere in one click.
type failures struct {
	mu     sync.Mutex
	byHost map[string]*Failed
	seen   map[string]time.Time // source+destination, to count retries once
}

// mihomo: [TCP] dial 节点 (match DomainSuffix/x) 127.0.0.1:1(curl, uid=1000) --> host:443 error: …
// The source carries the process when mihomo could find it.
var dialError = regexp.MustCompile(`\[(?:TCP|UDP)\] dial (.+?) \(match [^)]*\) (.+?) --> (\S+):(\d+) error: (.*?)"?$`)

func (f *failures) observe(line string, now time.Time) {
	m := dialError.FindStringSubmatch(line)
	if m == nil {
		return
	}
	via, src, host, port, msg := m[1], m[2], m[3], m[4], m[5]
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.byHost == nil {
		f.byHost, f.seen = map[string]*Failed{}, map[string]time.Time{}
	}
	key := src + ">" + host
	if t, ok := f.seen[key]; ok && now.Sub(t) < time.Minute {
		return // the kernel retries a connection several times
	}
	f.seen[key] = now
	e := f.byHost[host]
	if e == nil {
		e = &Failed{Host: host}
		f.byHost[host] = e
	}
	e.Port, e.Via, e.Error, e.Last = port, via, msg, now
	e.Count++
	if len(f.byHost) > 200 || len(f.seen) > 2000 {
		f.trim(now)
	}
}

func (f *failures) trim(now time.Time) {
	for k, t := range f.seen {
		if now.Sub(t) > time.Minute {
			delete(f.seen, k)
		}
	}
	if len(f.byHost) > 200 {
		list := f.listLocked()
		for _, e := range list[150:] {
			delete(f.byHost, e.Host)
		}
	}
}

func (f *failures) list() []Failed {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.listLocked()
}

func (f *failures) listLocked() []Failed {
	out := make([]Failed, 0, len(f.byHost))
	for _, e := range f.byHost {
		out = append(out, *e)
	}
	slices.SortFunc(out, func(a, b Failed) int { return b.Last.Compare(a.Last) })
	return out
}

func (f *failures) clear() {
	f.mu.Lock()
	f.byHost, f.seen = nil, nil
	f.mu.Unlock()
}

// Failed returns destinations that recently failed, newest first.
func (d *Daemon) Failed() []Failed { return d.failures.list() }

// ClearFailed forgets recorded failures.
func (d *Daemon) ClearFailed() { d.failures.clear() }

// Suggest proposes route targets for a host: its registrable domain first
// (api.openai.com → openai.com), then the host itself.
func Suggest(host string) []string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	out := []string{}
	if base, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil && base != host {
		out = append(out, base)
	}
	return append(out, host)
}
