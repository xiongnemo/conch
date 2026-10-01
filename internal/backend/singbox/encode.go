// Package singbox encodes compiled profiles into sing-box 1.14 configuration.
//
// Chains use detour, groups become selector and urltest outbounds, and the
// routing table becomes route rules evaluated in order. sing-box matches IP
// rules only against IP destinations unless a resolve action ran before,
// which is what nautilus' no-resolve default already means.
package singbox

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"runtime"
	"strconv"
	"strings"

	"nautilus/internal/backend"
	"nautilus/internal/compile"
	"nautilus/internal/diag"
	"nautilus/internal/lists"
	"nautilus/internal/route"
)

type Backend struct{}

func (Backend) Name() string { return "sing-box" }

func (Backend) Capabilities() backend.Capabilities {
	// sing-box finds processes on Linux, Windows and macOS.
	process := runtime.GOOS == "linux" || runtime.GOOS == "windows" || runtime.GOOS == "darwin"
	return backend.Capabilities{ProcessMatch: process, KeywordMatch: true, Chains: true, TUN: true}
}

const (
	inMixed = compile.HopSep + "mixed"
	inTUN   = compile.HopSep + "tun"
	// Where geosite:/geoip: categories come from, as for mihomo.
	ruleSetBase = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/"
	// An origin no page can have, so browsers may not call the API.
	corsNobody = "https://nautilus.invalid"
)

type encoder struct {
	r    *compile.Result
	opts backend.Options
	d    diag.List

	groups      map[string]bool
	needsReject bool // a group lists REJECT, which only a block outbound can be
	manifest    *backend.Manifest
	ruleSets    []ruleSet
}

func (Backend) Encode(r *compile.Result, opts backend.Options) (*backend.Artifact, diag.List) {
	e := &encoder{r: r, opts: opts, groups: map[string]bool{}}
	if opts.ControllerUnix != "" || opts.ControllerPipe != "" {
		e.d.Errorf(diag.Pos{}, "sing-box 的 API 只能监听 TCP 地址")
	}
	e.manifest = &backend.Manifest{Backend: "sing-box", Proxies: backend.ProxyManifest(r)}
	for _, g := range r.Groups {
		e.groups[g.Name] = true
	}

	cfg := config{Log: e.log()}
	cfg.Outbounds = append(cfg.Outbounds, outbound{Type: "direct", Tag: "DIRECT"})
	for _, p := range r.Proxies {
		o, ep, warns, err := e.nodeOutbound(p)
		if err != nil {
			e.d.Errorf(p.Node.Pos, "节点 %q：%v", p.Node.Name, err)
			continue
		}
		if p.Kind == compile.ProxyNode || p.Hop == 1 { // chain copies share their node's warnings
			for _, w := range warns {
				e.d.Warnf(p.Node.Pos, "节点 %q：%s", p.Node.Name, w)
			}
		}
		if ep != nil {
			cfg.Endpoints = append(cfg.Endpoints, *ep)
		} else {
			cfg.Outbounds = append(cfg.Outbounds, *o)
		}
	}
	for _, g := range r.Groups {
		cfg.Outbounds = append(cfg.Outbounds, e.group(g))
	}
	if e.needsReject {
		cfg.Outbounds = append(cfg.Outbounds, outbound{Type: "block", Tag: "REJECT"})
	}
	cfg.DNS, cfg.Route.DefaultDomainResolver = e.dns()
	cfg.Inbounds = e.inbounds()
	cfg.Route.Rules = e.rules()
	cfg.Route.RuleSet = e.ruleSets
	cfg.Route.Final = e.final()
	cfg.Route.AutoDetectInterface = true
	if opts.Controller != "" {
		cfg.Experimental = &experimental{
			ClashAPI:  &clashAPI{ExternalController: opts.Controller, Secret: opts.Secret, AccessControlAllowOrigin: []string{corsNobody}},
			CacheFile: &cacheFile{Enabled: true, StoreFakeIP: r.Settings.DNS.Enable && r.Settings.DNS.Mode == "fake-ip"},
		}
	}
	if e.d.HasErrors() {
		return nil, e.d
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		e.d.Errorf(diag.Pos{}, "生成 sing-box 配置：%v", err)
		return nil, e.d
	}
	return &backend.Artifact{Config: append(data, '\n'), Manifest: e.manifest}, e.d
}

func (e *encoder) log() logConfig {
	level := backend.LogLevel(e.r.Settings.LogLevel, e.opts.MinLogLevel)
	switch level {
	case "silent":
		return logConfig{Disabled: true}
	case "warning":
		level = "warn"
	}
	return logConfig{Level: level, Timestamp: true}
}

// group emits a group. sing-box only has selector and urltest, so groups
// that fail over or balance pick the fastest member instead.
func (e *encoder) group(g *compile.Group) outbound {
	members := make([]string, 0, len(g.Members))
	for _, m := range g.Members {
		if m == "REJECT" || m == "REJECT-DROP" {
			e.needsReject = true
			m = "REJECT"
		}
		members = append(members, m)
	}
	if g.Type == "select" {
		return outbound{Type: "selector", Tag: g.Name, Outbounds: members, Default: g.Selected}
	}
	if g.Type != "url-test" && g.Chain == "" {
		e.d.Warnf(g.Pos, "出口组 %q：sing-box 没有%s组，改为自动选择延迟最低的成员", g.Name, map[string]string{"fallback": "故障转移", "load-balance": "负载均衡"}[g.Type])
	}
	o := outbound{Type: "urltest", Tag: g.Name, Outbounds: members, URL: g.URL, Tolerance: g.Tolerance}
	if g.Interval > 0 {
		o.Interval = strconv.Itoa(g.Interval) + "s"
		if g.Interval > 30*60 {
			o.IdleTimeout = o.Interval // the interval may not exceed it
		}
	}
	return o
}

// final is where traffic no rule matched goes.
func (e *encoder) final() string {
	switch e.r.Settings.Mode {
	case "global":
		return compile.GlobalGroup
	case "direct":
		return "DIRECT"
	}
	for _, r := range e.r.Rules {
		if r.Match == route.MatchFinal && r.Target != "REJECT" && r.Target != "REJECT-DROP" {
			return r.Target
		}
	}
	return "DIRECT"
}

func (e *encoder) inbounds() []inbound {
	s := e.r.Settings
	listen := "127.0.0.1"
	if s.AllowLAN {
		listen = cmpOr(s.BindAddress, "0.0.0.0")
	}
	ins := []inbound{{Type: "mixed", Tag: inMixed, Listen: listen, ListenPort: s.MixedPort}}
	for _, f := range e.opts.Forwards {
		ins = append(ins, inbound{Type: "socks", Tag: f.Name, Listen: "127.0.0.1", ListenPort: f.Port})
	}
	if s.TUN.Enable {
		ins = append(ins, inbound{Type: "tun", Tag: inTUN, Address: []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
			AutoRoute: true, StrictRoute: s.TUN.StrictRoute, Stack: s.TUN.Stack})
	}
	return ins
}

// rules evaluates in order: sniffing (so domain rules see domains even
// for clients that connect by IP), DNS hijacking under TUN, the loopback
// inbounds of sidecars, and then the routing table.
func (e *encoder) rules() []rule {
	out := []rule{{Action: "sniff"}}
	if e.r.Settings.TUN.Enable {
		out = append(out, rule{Protocol: "dns", Action: "hijack-dns"})
	}
	for _, f := range e.opts.Forwards {
		out = append(out, rule{Inbound: []string{f.Name}, Action: "route", Outbound: f.Via})
	}
	if e.r.Settings.Mode != "rule" {
		return out // global and direct only use the final outbound
	}
	resolved := false
	descs := map[string]int{} // description → compiled rule, -1 when ambiguous
	type emitted struct {
		index int
		rule  rule
	}
	var user []emitted
	for i, r := range e.r.Rules {
		var xs []rule
		switch r.Match {
		case route.MatchProcessName:
			xs = []rule{{ProcessName: []string{r.Value}}}
		case route.MatchProcessPath:
			xs = []rule{{ProcessPath: []string{r.Value}}}
		case route.MatchDomain:
			xs = []rule{{Domain: []string{r.Value}}}
		case route.MatchDomainSuffix:
			xs = []rule{{DomainSuffix: []string{r.Value}}}
		case route.MatchDomainKeyword:
			xs = []rule{{DomainKeyword: []string{r.Value}}}
		case route.MatchIPCIDR:
			xs = []rule{{IPCIDR: []string{r.Value}}}
			if !r.NoResolve && !resolved {
				// From here on, IP rules also see the domain's addresses.
				out = append(out, rule{Action: "resolve"})
				resolved = true
			}
		case route.MatchRuleSet:
			xs = e.listRules(r)
		case route.MatchDstPort:
			xs = []rule{portRule(r.Value)}
		case route.MatchNetwork:
			xs = []rule{{Network: strings.Split(strings.ToLower(r.Value), ",")}}
		case route.MatchRaw:
			if !r.Origin.Imported {
				e.d.Errorf(r.Origin.Pos, "sing-box 不支持 clash 原始规则")
			}
			continue // imported ones are reported by backend.Check
		case route.MatchFinal:
			continue
		default:
			e.d.Errorf(r.Origin.Pos, "sing-box 不支持这种规则（%s）", r.Origin.Key)
			continue
		}
		for _, x := range xs {
			setTarget(&x, r.Target)
			user = append(user, emitted{i, x})
			d := describe(x)
			if old, ok := descs[d]; ok && old != i {
				descs[d] = -1
			} else {
				descs[d] = i
			}
		}
	}
	for _, u := range user {
		out = append(out, u.rule)
		data, _ := json.Marshal(u.rule)
		r := e.r.Rules[u.index]
		mr := backend.ManifestRule{Index: u.index, Rule: string(data), Tier: r.Origin.Tier.String(), Key: r.Origin.Key, Source: r.Origin.Pos.String(), Builtin: r.Origin.Builtin}
		if d := describe(u.rule); descs[d] == u.index {
			mr.Tag = d // how sing-box names the rule a connection matched
		}
		e.manifest.Rules = append(e.manifest.Rules, mr)
	}
	return out
}

func setTarget(r *rule, target string) {
	switch target {
	case "REJECT":
		r.Action = "reject"
	case "REJECT-DROP":
		r.Action, r.Method = "reject", "drop"
	default:
		r.Action, r.Outbound = "route", target
	}
}

func portRule(value string) rule {
	var r rule
	for _, p := range strings.Split(value, ",") {
		p = strings.TrimSpace(p)
		if lo, hi, ok := strings.Cut(p, "-"); ok {
			r.PortRange = append(r.PortRange, lo+":"+hi)
		} else if n, err := strconv.Atoi(p); err == nil {
			r.Port = append(r.Port, n)
		}
	}
	return r
}

// listRules turns a rule list into sing-box rules: geosite/geoip
// categories as remote rule sets, other lists inlined.
func (e *encoder) listRules(r route.Rule) []rule {
	var p route.Provider
	for _, q := range e.r.Providers {
		if q.Name == r.Value {
			p = q
		}
	}
	if p.Geo != "" {
		tag := p.Geo + "-" + p.Category
		e.addRuleSet(ruleSet{Type: "remote", Tag: tag, Format: "binary", URL: ruleSetBase + p.Geo + "/" + p.Category + ".srs", UpdateInterval: "1d"})
		return []rule{{RuleSet: []string{tag}}}
	}
	if p.Format == "mrs" {
		e.listProblem(r, "sing-box 无法读取 mrs 格式的规则列表 %s，请改用 yaml 或 text 格式的版本", p.URL)
		return nil
	}
	var entries []lists.Entry
	var skipped []string
	var err error
	switch {
	case p.URL == "":
		entries, skipped, err = lists.Parse([]byte(strings.Join(p.Payload, "\n")), "text", p.Behavior)
	case e.opts.Lists == nil:
		e.listProblem(r, "sing-box 需要先下载规则列表 %s", p.URL)
		return nil
	default:
		entries, skipped, err = e.opts.Lists(p)
	}
	if p.Format == "autoproxy" {
		entries = lists.Select(entries, p.Exceptions)
		if len(entries) == 0 && err == nil {
			return nil
		}
	}
	if err != nil {
		e.listProblem(r, "%v", err)
		return nil
	}
	if len(skipped) > 0 && !p.Exceptions {
		e.d.Warnf(r.Origin.Pos, "规则列表 %s 中有 %d 条 sing-box 无法表达的规则，已跳过（例如 %q）", p.URL, len(skipped), skipped[0])
	}
	return entryRules(e, entries)
}

func (e *encoder) addRuleSet(rs ruleSet) {
	for _, x := range e.ruleSets {
		if x.Tag == rs.Tag {
			return
		}
	}
	// Downloaded through the proxy traffic would take anyway.
	if f := e.final(); f != "DIRECT" {
		rs.HTTPClient.Detour = f
	}
	e.ruleSets = append(e.ruleSets, rs)
}

func (e *encoder) listProblem(r route.Rule, format string, args ...any) {
	if r.Origin.Imported {
		e.d.Warnf(r.Origin.Pos, "已跳过订阅 %q 的一个规则集："+format, append([]any{r.Origin.Key}, args...)...)
		return
	}
	e.d.Errorf(r.Origin.Pos, format, args...)
}

// entryRules groups list entries into rules. Within a rule sing-box ORs
// the destination fields (domains and IPs) and ANDs the rest, so
// processes, ports and networks get rules of their own.
func entryRules(e *encoder, entries []lists.Entry) []rule {
	var dest, procs, ports, networks rule
	for _, en := range entries {
		switch en.Kind {
		case lists.Domain:
			dest.Domain = append(dest.Domain, en.Value)
		case lists.DomainSuffix:
			dest.DomainSuffix = append(dest.DomainSuffix, en.Value)
		case lists.DomainKeyword:
			dest.DomainKeyword = append(dest.DomainKeyword, en.Value)
		case lists.DomainRegex:
			dest.DomainRegex = append(dest.DomainRegex, en.Value)
		case lists.IPCIDR:
			dest.IPCIDR = append(dest.IPCIDR, en.Value)
		case lists.GeoSite, lists.GeoIP:
			kind := map[lists.Kind]string{lists.GeoSite: "geosite", lists.GeoIP: "geoip"}[en.Kind]
			tag := kind + "-" + strings.ToLower(en.Value)
			e.addRuleSet(ruleSet{Type: "remote", Tag: tag, Format: "binary", URL: ruleSetBase + kind + "/" + strings.ToLower(en.Value) + ".srs", UpdateInterval: "1d"})
			dest.RuleSet = append(dest.RuleSet, tag)
		case lists.ProcessName:
			procs.ProcessName = append(procs.ProcessName, en.Value)
		case lists.ProcessPath:
			procs.ProcessPath = append(procs.ProcessPath, en.Value)
		case lists.DstPort:
			p := portRule(en.Value)
			ports.Port, ports.PortRange = append(ports.Port, p.Port...), append(ports.PortRange, p.PortRange...)
		case lists.Network:
			networks.Network = append(networks.Network, strings.ToLower(en.Value))
		}
	}
	var out []rule
	// A rule with rule sets and other destination fields would AND them.
	if len(dest.RuleSet) > 0 && (len(dest.Domain)+len(dest.DomainSuffix)+len(dest.DomainKeyword)+len(dest.DomainRegex)+len(dest.IPCIDR) > 0) {
		out = append(out, rule{RuleSet: dest.RuleSet})
		dest.RuleSet = nil
	}
	for _, r := range []rule{dest, procs, ports, networks} {
		if describe(r) != "" {
			out = append(out, r)
		}
	}
	return out
}

// describe renders a rule the way sing-box names it in connections, so
// they can be traced to the entry or list that routed them.
func describe(r rule) string {
	var items []string
	list := func(name string, vs []string, cut bool) {
		switch {
		case len(vs) == 0:
		case len(vs) == 1:
			items = append(items, name+"="+vs[0])
		case cut && len(vs) > 3:
			items = append(items, name+"=["+strings.Join(vs[:3], " ")+"...]")
		default:
			items = append(items, name+"=["+strings.Join(vs, " ")+"]")
		}
	}
	list("network", r.Network, false)
	if len(r.Domain)+len(r.DomainSuffix) > 0 {
		before := len(items)
		list("domain", r.Domain, true)
		list("domain_suffix", r.DomainSuffix, true)
		if len(items)-before == 2 { // one item in sing-box
			items = append(items[:before], items[before]+" "+items[before+1])
		}
	}
	list("domain_keyword", r.DomainKeyword, true)
	if len(r.DomainRegex) > 3 {
		items = append(items, "domain_regex=["+strings.Join(r.DomainRegex[:3], " ")+"]")
	} else {
		list("domain_regex", r.DomainRegex, false)
	}
	list("ip_cidr", r.IPCIDR, true)
	var ports []string
	for _, p := range r.Port {
		ports = append(ports, strconv.Itoa(p))
	}
	list("port", ports, false)
	list("port_range", r.PortRange, false)
	list("process_name", r.ProcessName, false)
	list("process_path", r.ProcessPath, false)
	list("rule_set", r.RuleSet, false)
	return strings.Join(items, " ")
}

// dns lists the profile's resolvers in sing-box's typed form and returns
// the one outbounds resolve their servers' names with.
func (e *encoder) dns() (*dnsConfig, string) {
	s := e.r.Settings.DNS
	cfg := &dnsConfig{Strategy: "ipv4_only"}
	if s.IPv6 {
		cfg.Strategy = "prefer_ipv4"
	}
	resolver := ""
	needLocal := false
	for i, ns := range s.Nameservers {
		srv, err := dnsServerOf(ns)
		if err != nil {
			e.d.Warnf(diag.Pos{}, "DNS 服务器 %q：%v，已跳过", ns, err)
			continue
		}
		srv.Tag = "dns-" + strconv.Itoa(i+1)
		if net.ParseIP(srv.Server) == nil && srv.Type != "local" {
			srv.DomainResolver, needLocal = "local", true // a name needs resolving first
		} else if resolver == "" {
			resolver = srv.Tag
		}
		cfg.Servers = append(cfg.Servers, srv)
	}
	if needLocal || len(cfg.Servers) == 0 {
		cfg.Servers = append(cfg.Servers, dnsServer{Type: "local", Tag: "local"})
	}
	if resolver == "" {
		resolver = "local"
	}
	cfg.Final = cfg.Servers[0].Tag
	if s.Enable && s.Mode == "fake-ip" {
		cfg.Servers = append(cfg.Servers, dnsServer{Type: "fakeip", Tag: "fakeip", Inet4Range: "198.18.0.0/15", Inet6Range: "fc00::/18"})
		cfg.Rules = []dnsRule{{QueryType: []string{"A", "AAAA"}, Server: "fakeip"}}
	}
	return cfg, resolver
}

// dnsServerOf reads mihomo's nameserver syntax: https://1.1.1.1/dns-query,
// tls://1.1.1.1, quic://…, tcp://…, udp://… or a bare address.
func dnsServerOf(ns string) (dnsServer, error) {
	if ns == "system" || ns == "local" {
		return dnsServer{Type: "local"}, nil
	}
	if !strings.Contains(ns, "://") {
		ns = "udp://" + ns
	}
	u, err := url.Parse(ns)
	if err != nil {
		return dnsServer{}, err
	}
	typ := map[string]string{"https": "https", "tls": "tls", "quic": "quic", "h3": "h3", "tcp": "tcp", "udp": "udp"}[u.Scheme]
	if typ == "" {
		return dnsServer{}, fmt.Errorf("sing-box 不支持 %s:// 形式的 DNS", u.Scheme)
	}
	s := dnsServer{Type: typ, Server: u.Hostname()}
	if p, err := strconv.Atoi(u.Port()); err == nil {
		s.ServerPort = p
	}
	if typ == "https" || typ == "h3" {
		s.Path = u.Path
		if s.Path == "/dns-query" {
			s.Path = "" // the default
		}
	}
	return s, nil
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
