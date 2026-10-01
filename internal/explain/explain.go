// Package explain answers "where would this connection go, and why?" by
// evaluating a compiled routing table locally, with each backend's
// matching semantics.
package explain

import (
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"nautilus/internal/compile"
	"nautilus/internal/lists"
	"nautilus/internal/route"
)

// Query describes a connection.
type Query struct {
	Host    string // domain or IP literal
	Port    int    // 0 when unknown
	Process string // process name or path; empty when unknown
	Network string // tcp or udp
}

// ParseQuery reads what users type: a host, an IP, host:port or a URL.
func ParseQuery(arg string) Query {
	arg = strings.TrimSpace(arg)
	q := Query{Host: arg}
	if u, err := url.Parse(arg); err == nil && u.Host != "" {
		q.Host = u.Hostname()
		if p, err := strconv.Atoi(u.Port()); err == nil {
			q.Port = p
		} else if u.Scheme == "https" {
			q.Port = 443
		} else if u.Scheme == "http" {
			q.Port = 80
		}
		return q
	}
	if h, p, err := net.SplitHostPort(arg); err == nil {
		q.Host = h
		q.Port, _ = strconv.Atoi(p)
	}
	return q
}

// Hit is a rule that matches, or might match, the query.
type Hit struct {
	Index int
	Rule  route.Rule
	Note  string
}

// Explanation is the outcome of a query.
type Explanation struct {
	Target    string // outbound the connection goes to
	Matched   *Hit   // nil when the connection falls to the default route
	Shadowed  []Hit  // later rules that would also have matched
	Uncertain []Hit  // earlier rules whose outcome cannot be decided locally
	Resolved  []netip.Addr
	// AfterResolve is true when an IP rule only matched once the domain
	// was resolved (xray's IPIfNonMatch, or a mihomo rule without no-resolve).
	AfterResolve bool
}

// Explainer evaluates queries against a compiled profile.
type Explainer struct {
	Result *compile.Result
	// Xray selects xray semantics: every domain-based rule is tried before
	// the domain is resolved for IP rules, and the default route is used
	// when nothing matches.
	Xray bool
	// Lists loads a rule set's entries; nil marks rule sets as uncertain.
	Lists func(p route.Provider) ([]lists.Entry, error)
	// Resolve looks up a domain for IP rules; nil means never resolve.
	Resolve func(host string) ([]netip.Addr, error)

	cache map[string][]lists.Entry
}

type verdict int

const (
	no verdict = iota
	yes
	unknown
	needIP // matches only if the domain resolves into the rule
)

func (e *Explainer) Explain(q Query) *Explanation {
	if q.Network == "" {
		q.Network = "tcp"
	}
	ex := &Explanation{}
	if e.Result.Settings.Mode != "rule" {
		ex.Target = compile.GlobalGroup
		if e.Result.Settings.Mode == "direct" {
			ex.Target = "DIRECT"
		}
		return ex
	}
	c := &conn{q: q, host: strings.ToLower(strings.TrimSuffix(q.Host, "."))}
	if a, err := netip.ParseAddr(c.host); err == nil {
		c.ip = a.Unmap()
	} else {
		c.domain = true
	}
	resolve := func() bool {
		if c.ip.IsValid() {
			return true
		}
		if e.Resolve == nil || !c.domain {
			return false
		}
		addrs, err := e.Resolve(c.host)
		if err != nil || len(addrs) == 0 {
			return false
		}
		c.ip = addrs[0].Unmap()
		// Resolving after the match only serves the shadowed list.
		if ex.Matched == nil {
			ex.Resolved, ex.AfterResolve = addrs, true
		}
		return true
	}
	rules := e.Result.Rules
	record := func(i int, v verdict, note string) {
		hit := Hit{Index: i, Rule: rules[i], Note: note}
		switch {
		case v == yes && ex.Matched == nil:
			ex.Matched, ex.Target = &hit, rules[i].Target
		case v == yes && rules[i].Match != route.MatchFinal:
			ex.Shadowed = append(ex.Shadowed, hit)
		case v != no && ex.Matched == nil:
			ex.Uncertain = append(ex.Uncertain, hit)
		}
	}

	if !e.Xray {
		// mihomo: first match. A rule without no-resolve resolves the
		// domain when it needs an IP; with no-resolve it only sees an IP
		// that is already known.
		for i, r := range rules {
			v, note := e.match(r, c)
			if v == needIP {
				switch {
				case r.NoResolve:
					v = no
				case resolve():
					v, note = e.match(r, c)
				}
			}
			record(i, v, note)
		}
		return ex
	}

	// xray IPIfNonMatch: every rule is tried without resolving; only if
	// none matched is the domain resolved and the rules tried again.
	var pending []int
	for i, r := range rules {
		if r.Match == route.MatchFinal {
			continue
		}
		v, note := e.match(r, c)
		if v == needIP {
			pending = append(pending, i)
			continue
		}
		record(i, v, note)
	}
	if ex.Matched == nil {
		if resolve() {
			for _, i := range pending {
				if v, note := e.match(rules[i], c); v == yes {
					record(i, v, note)
				}
			}
		} else {
			for _, i := range pending {
				record(i, needIP, "取决于域名解析出的 IP")
			}
		}
	}
	if ex.Matched == nil {
		for _, r := range rules {
			if r.Match == route.MatchFinal {
				ex.Target = r.Target // xray's first outbound
			}
		}
	}
	return ex
}

// Relevant drops uncertain rules that would not change the outcome.
func (ex *Explanation) Relevant() []Hit {
	var out []Hit
	for _, h := range ex.Uncertain {
		if h.Rule.Target != ex.Target {
			out = append(out, h)
		}
	}
	return out
}

// conn is the connection being explained.
type conn struct {
	q      Query
	host   string
	domain bool       // the host is a name, not an IP literal
	ip     netip.Addr // the literal, or the resolved address once known
}

// match decides one rule. Domain rules need a host name; IP rules need an
// address, and report needIP for a domain that has not been resolved.
func (e *Explainer) match(r route.Rule, c *conn) (verdict, string) {
	q := c.q
	switch r.Match {
	case route.MatchDomain:
		return boolV(c.domain && c.host == r.Value), ""
	case route.MatchDomainSuffix:
		return boolV(c.domain && suffix(c.host, r.Value)), ""
	case route.MatchDomainKeyword:
		return boolV(c.domain && strings.Contains(c.host, r.Value)), ""
	case route.MatchIPCIDR:
		return ipMatch(r.Value, c.ip)
	case route.MatchProcessName, route.MatchProcessPath:
		if q.Process == "" {
			return unknown, "取决于发起连接的应用"
		}
		if r.Match == route.MatchProcessPath {
			return boolV(q.Process == r.Value), ""
		}
		return boolV(strings.EqualFold(filepath.Base(q.Process), r.Value)), ""
	case route.MatchDstPort:
		if q.Port == 0 {
			return unknown, "取决于端口"
		}
		return boolV(portMatch(r.Value, q.Port)), ""
	case route.MatchNetwork:
		return boolV(strings.EqualFold(r.Value, q.Network)), ""
	case route.MatchRuleSet:
		return e.ruleSet(r.Value, c)
	case route.MatchFinal:
		return yes, ""
	}
	return unknown, "这条规则需要内核在运行时判断"
}

func (e *Explainer) ruleSet(name string, c *conn) (verdict, string) {
	host, isDomain, ip, q := c.host, c.domain, c.ip, c.q
	var p route.Provider
	for _, x := range e.Result.Providers {
		if x.Name == name {
			p = x
		}
	}
	entries, ok := e.entries(p)
	if !ok {
		return unknown, "无法在本地读取这个规则列表"
	}
	best := no
	for _, en := range entries {
		v := no
		switch en.Kind {
		case lists.Domain:
			v = boolV(isDomain && host == en.Value)
		case lists.DomainSuffix:
			v = boolV(isDomain && suffix(host, en.Value))
		case lists.DomainKeyword:
			v = boolV(isDomain && strings.Contains(host, en.Value))
		case lists.DomainRegex:
			re, err := regexp.Compile(en.Value)
			v = boolV(isDomain && err == nil && re.MatchString(host))
		case lists.IPCIDR:
			v, _ = ipMatch(en.Value, ip)
		case lists.DstPort:
			v = boolV(q.Port != 0 && portMatch(en.Value, q.Port))
		case lists.Network:
			v = boolV(strings.EqualFold(en.Value, q.Network))
		default:
			v = unknown // nested geodata, processes
		}
		if v == yes {
			return yes, ""
		}
		if v > best {
			best = v
		}
	}
	return best, ""
}

func (e *Explainer) entries(p route.Provider) ([]lists.Entry, bool) {
	if e.cache == nil {
		e.cache = map[string][]lists.Entry{}
	}
	if entries, ok := e.cache[p.Name]; ok {
		return entries, entries != nil
	}
	var entries []lists.Entry
	var err error
	switch {
	case p.URL == "" && p.Payload != nil:
		entries, _, err = lists.Parse([]byte(strings.Join(p.Payload, "\n")), "text", p.Behavior)
	case e.Lists != nil:
		q := p
		if p.TextURL != "" { // geosite/geoip categories have a text twin
			q.URL, q.Format = p.TextURL, "text"
		}
		if q.Format == "mrs" {
			err = errUnreadable
		} else {
			entries, err = e.Lists(q)
		}
	default:
		err = errUnreadable
	}
	if err != nil {
		entries = nil
	}
	if p.Format == "autoproxy" && entries != nil {
		entries = lists.Select(entries, p.Exceptions)
		if entries == nil {
			entries = []lists.Entry{} // readable, just empty
		}
	}
	e.cache[p.Name] = entries
	return entries, entries != nil
}

type errorString string

func (e errorString) Error() string { return string(e) }

const errUnreadable = errorString("unreadable")

func ipMatch(cidr string, ip netip.Addr) (verdict, string) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return no, ""
	}
	if !ip.IsValid() {
		return needIP, "取决于域名解析出的 IP"
	}
	return boolV(p.Contains(ip)), ""
}

func suffix(host, domain string) bool {
	return host == domain || strings.HasSuffix(host, "."+domain)
}

// portMatch accepts mihomo port specs such as "443", "80/443" or "1000-2000".
func portMatch(spec string, port int) bool {
	for part := range strings.FieldsFuncSeq(spec, func(r rune) bool { return r == '/' || r == ',' }) {
		lo, hi, isRange := strings.Cut(part, "-")
		a, err1 := strconv.Atoi(strings.TrimSpace(lo))
		b := a
		var err2 error
		if isRange {
			b, err2 = strconv.Atoi(strings.TrimSpace(hi))
		}
		if err1 == nil && err2 == nil && port >= a && port <= b {
			return true
		}
	}
	return false
}

func boolV(b bool) verdict {
	if b {
		return yes
	}
	return no
}
