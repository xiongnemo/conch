package daemon

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"

	"nautilus/internal/backend"
	"nautilus/internal/compile"
	"nautilus/internal/control"
	"nautilus/internal/explain"
	"nautilus/internal/route"
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
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	res, art := d.res, d.art
	d.mu.Unlock()
	out := make([]Connection, 0, len(conns))
	if res == nil || art == nil {
		for _, c := range conns {
			via := slices.Clone(c.Chains)
			slices.Reverse(via)
			out = append(out, Connection{Connection: c, Matched: c.Rule + " " + c.RulePayload, Via: via})
		}
		return out, nil
	}
	byLine, byTag := map[string]int{}, map[string][2]int{}
	for _, mr := range art.Manifest.Rules {
		if max(mr.Index, mr.Last) >= len(res.Rules) {
			continue
		}
		if mr.Tag != "" {
			byTag[mr.Tag] = [2]int{mr.Index, max(mr.Last, mr.Index)}
			continue
		}
		fields := strings.Split(mr.Rule, ",")
		payload := ""
		if len(fields) > 2 {
			payload = fields[1]
		}
		byLine[ruleKey(fields[0], payload)] = mr.Index
	}
	final := slices.IndexFunc(res.Rules, func(r route.Rule) bool { return r.Match == route.MatchFinal })
	names := kernelNames(art)
	for _, c := range conns {
		idx, ok, merged := 0, false, 0
		if span, found := byTag[c.RuleTag]; found {
			// A kernel rule merged from several (xray): the one that matches.
			idx, ok = span[0], true
			if span[1] > span[0] {
				merged = span[1] - span[0] + 1
				for i := span[0]; i <= span[1]; i++ {
					if explain.Matches(res.Rules[i], c.Host) {
						idx, merged = i, 0
						break
					}
				}
			}
		} else {
			idx, ok = byLine[ruleKey(c.Rule, c.RulePayload)]
		}
		if !ok && strings.EqualFold(c.Rule, "match") && final >= 0 {
			idx, ok = final, true // xray's default route has no rule
		}
		var via []string
		for _, tag := range slices.Backward(c.Chains) {
			if name := names(tag); !strings.Contains(name, compile.HopSep) || isHop(res, name) {
				via = append(via, hopName(res, name))
			}
		}
		matched := cmpOr(c.Rule+" "+c.RulePayload, c.RuleTag)
		switch {
		case res.Settings.Mode != "rule":
			matched = fmt.Sprintf("当前是 %s 模式", res.Settings.Mode)
		case ok && merged > 0:
			matched = fmt.Sprintf("订阅 %s 的 %d 条规则之一", res.Rules[idx].Origin.Key, merged)
			if target := res.Rules[idx].Target; len(via) == 0 || via[0] != target {
				via = append([]string{target}, via...)
			}
		case ok:
			matched = view.Rule(res.Rules[idx])
			// Rules that send traffic to a group straight to its balancer
			// (xray) do not name the group in the connection.
			if target := res.Rules[idx].Target; len(via) == 0 || via[0] != target {
				via = append([]string{target}, via...)
			}
		}
		out = append(out, Connection{Connection: c, Matched: matched, Via: via})
	}
	slices.SortFunc(out, func(a, b Connection) int { return b.Start.Compare(a.Start) })
	return out, nil
}

// kernelNames maps the kernel's identifiers for outbounds back to names.
func kernelNames(art *backend.Artifact) func(string) string {
	byTag := map[string]string{}
	for name, tag := range art.Manifest.Tags {
		byTag[tag] = name
	}
	return func(tag string) string { return cmpOr(byTag[tag], tag) }
}

func isHop(res *compile.Result, name string) bool {
	return slices.ContainsFunc(res.Proxies, func(p *compile.Proxy) bool { return p.Name == name && p.Kind == compile.ProxyChainHop })
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

func (f *failures) add(x control.DialFailure, now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.byHost == nil {
		f.byHost, f.seen = map[string]*Failed{}, map[string]time.Time{}
	}
	key := x.Source + ">" + x.Host
	if t, ok := f.seen[key]; ok && now.Sub(t) < time.Minute {
		return // the kernel retries a connection several times
	}
	f.seen[key] = now
	e := f.byHost[x.Host]
	if e == nil {
		e = &Failed{Host: x.Host}
		f.byHost[x.Host] = e
	}
	e.Port, e.Via, e.Error, e.Last = x.Port, x.Via, x.Error, now
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
