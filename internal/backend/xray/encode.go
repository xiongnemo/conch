// Package xray encodes compiled profiles into Xray-core configuration.
//
// Groups become balancers. Each group also gets a loopback outbound that
// re-enters routing with a group-specific inbound tag, so groups can be
// nested inside other groups and used as the first hop of a chain (via
// sockopt.dialerProxy), neither of which balancers support directly.
//
// Routing uses domainStrategy IPIfNonMatch and no catch-all rule: when no
// rule matches, xray resolves the domain, matches IP rules again, and only
// then falls back to the first outbound, which is the default route.
package xray

import (
	"cmp"
	"encoding/json"
	"fmt"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"nautilus/internal/backend"
	"nautilus/internal/compile"
	"nautilus/internal/diag"
	"nautilus/internal/lists"
	"nautilus/internal/route"
)

type Backend struct{}

func (Backend) Name() string { return "xray" }

func (Backend) Capabilities() backend.Capabilities {
	// xray v26.3.27 finds processes on Windows and Linux only.
	return backend.Capabilities{ProcessMatch: runtime.GOOS != "darwin", KeywordMatch: true, Chains: true}
}

const (
	inMixed       = compile.HopSep + "mixed"
	groupInPrefix = compile.HopSep + "group" + compile.HopSep
	apiTag        = compile.HopSep + "api"
)

var builtins = []string{"DIRECT", "REJECT", "REJECT-DROP"}

type encoder struct {
	r      *compile.Result
	opts   backend.Options
	d      diag.List
	tags   map[string]string
	groups map[string]*compile.Group

	outbounds []outbound
	dispatch  []rule // loopback inbound → balancer, evaluated first
	balancers []balancer
	observed  []*compile.Group
	manifest  *backend.Manifest
}

func (Backend) Encode(r *compile.Result, opts backend.Options) (*backend.Artifact, diag.List) {
	e := &encoder{r: r, opts: opts, groups: map[string]*compile.Group{}}
	if opts.ControllerPipe != "" {
		e.d.Errorf(diag.Pos{}, "xray 的 API 不能监听 Windows 命名管道，请改用 --controller-unix")
	}
	e.assignTags()
	e.manifest = &backend.Manifest{Backend: "xray", Proxies: backend.ProxyManifest(r)}
	for name, tag := range e.tags {
		if tag != name && !strings.HasPrefix(name, compile.HopSep) {
			if e.manifest.Tags == nil {
				e.manifest.Tags = map[string]string{}
			}
			e.manifest.Tags[name] = tag
		}
	}

	e.builtinOutbounds()
	e.nodeOutbounds()
	for _, g := range r.Groups {
		e.group(g)
	}
	rules := e.rules()
	if e.d.HasErrors() {
		return nil, e.d
	}

	cfg := config{
		Log:       logConfig{LogLevel: logLevel(backend.LogLevel(r.Settings.LogLevel, opts.MinLogLevel))},
		Inbounds:  []inbound{e.mixedInbound()},
		Outbounds: e.defaultFirst(),
		Routing: routing{
			DomainStrategy: "IPIfNonMatch",
			Rules:          append(e.dispatch, rules...),
			Balancers:      e.balancers,
		},
		Observatory: e.observatory(),
	}
	if s := r.Settings.DNS; s.Enable {
		cfg.DNS = &dnsConfig{Servers: localDNS(s.Nameservers), QueryStrategy: "UseIPv4"}
		if s.IPv6 {
			cfg.DNS.QueryStrategy = "UseIP"
		}
	}
	if opts.ControllerUnix != "" || opts.Controller != "" {
		services := []string{"HandlerService", "RoutingService", "StatsService"}
		if cfg.Observatory != nil {
			services = append(services, "ObservatoryService")
		}
		cfg.API = &apiConfig{Tag: apiTag, Listen: opts.Controller, Services: services}
		cfg.Stats = &struct{}{}
		cfg.Policy = &policyConfig{System: policySystem{true, true, true, true}}
		if opts.ControllerUnix != "" {
			// api.listen only accepts TCP at runtime. A dokodemo-door inbound
			// on a unix socket, routed to the API, serves it instead. It needs
			// a destination port even though nothing is dialed (xray panics
			// without one), and must list "unix" to create the socket.
			cfg.Inbounds = append(cfg.Inbounds, inbound{
				Tag:      apiTag,
				Protocol: "dokodemo-door",
				Listen:   opts.ControllerUnix,
				Settings: apiInboundSettings{Address: "127.0.0.1", Port: 1, Network: "unix"},
			})
			internal := []rule{{InboundTag: []string{apiTag}, OutboundTag: apiTag, RuleTag: apiTag}}
			// xray has no delay-test API. Each probe is an HTTP proxy on a
			// unix socket whose balancer nautilus overrides to the outbound
			// under test, so tests go through the very outbound users use.
			for i, socket := range opts.Probes {
				tag := ProbeTag(i)
				cfg.Inbounds = append(cfg.Inbounds, inbound{Tag: tag, Protocol: "http", Listen: socket})
				internal = append(internal, rule{InboundTag: []string{tag}, BalancerTag: tag, RuleTag: tag})
				cfg.Routing.Balancers = append(cfg.Routing.Balancers, balancer{Tag: tag, Selector: []string{e.tags["DIRECT"]}, Strategy: strategy{"random"}})
			}
			cfg.Routing.Rules = append(internal, cfg.Routing.Rules...)
		}
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		e.d.Errorf(diag.Pos{}, "生成 xray 配置：%v", err)
		return nil, e.d
	}
	return &backend.Artifact{Config: append(data, '\n'), Manifest: e.manifest}, e.d
}

// assignTags names every outbound, including the internal loopbacks that
// chain fallback balancers together.
func (e *encoder) assignTags() {
	names := slices.Clone(builtins)
	for _, p := range e.r.Proxies {
		names = append(names, p.Name)
	}
	for _, g := range e.r.Groups {
		e.groups[g.Name] = g
		names = append(names, g.Name)
		if g.Type == "fallback" {
			for i := 2; i <= len(g.Members); i++ {
				names = append(names, fallbackName(g.Name, i))
			}
		}
	}
	e.tags = assignTags(names)
}

func fallbackName(group string, i int) string {
	return group + compile.HopSep + "fallback" + compile.HopSep + strconv.Itoa(i)
}

func (e *encoder) builtinOutbounds() {
	e.outbounds = append(e.outbounds,
		outbound{Tag: e.tags["DIRECT"], Protocol: "freedom"},
		outbound{Tag: e.tags["REJECT"], Protocol: "blackhole"},
		outbound{Tag: e.tags["REJECT-DROP"], Protocol: "blackhole"},
	)
}

func (e *encoder) nodeOutbounds() {
	warned := map[any]bool{}
	for _, p := range e.r.Proxies {
		o, warns, err := e.nodeOutbound(p)
		if err != nil {
			e.d.Errorf(p.Node.Pos, "节点 %q：%v", p.Node.Name, err)
			continue
		}
		// Chain clones share their node's warnings; report them once.
		if !warned[p.Node] {
			warned[p.Node] = true
			for _, w := range warns {
				e.d.Warnf(p.Node.Pos, "节点 %q：%s", p.Node.Name, w)
			}
		}
		e.outbounds = append(e.outbounds, o)
	}
}

// group emits a group's balancer(s) and its loopback outbound.
func (e *encoder) group(g *compile.Group) {
	members := make([]string, len(g.Members))
	for i, m := range g.Members {
		members[i] = e.tags[m]
	}
	e.loopback(g.Name)
	switch g.Type {
	case "select":
		// The selection lives in the selector; at runtime nautilus switches
		// it instantly through RoutingService.OverrideBalancerTarget.
		selected := members[0]
		if g.Selected != "" {
			selected = e.tags[g.Selected]
		}
		e.balancers = append(e.balancers, balancer{Tag: g.Name, Selector: []string{selected}, Strategy: strategy{"random"}})
	case "url-test":
		// leastPing returns nothing until the first probe finishes; fall
		// back to the first member instead of the default route meanwhile.
		e.balancers = append(e.balancers, balancer{Tag: g.Name, Selector: members, Strategy: strategy{"leastPing"}, FallbackTag: members[0]})
		e.observed = append(e.observed, g)
	case "load-balance":
		typ := "random"
		switch g.Strategy {
		case "round-robin":
			typ = "roundRobin"
		case "", "random":
		default:
			e.d.Warnf(g.Pos, "出口组 %q：xray 不支持 %s 负载均衡，改为随机选择", g.Name, g.Strategy)
		}
		// random and roundRobin only skip dead members when a fallback is
		// set; without one they keep picking members the observatory
		// knows are down.
		e.balancers = append(e.balancers, balancer{Tag: g.Name, Selector: members, Strategy: strategy{typ}, FallbackTag: members[0]})
		e.observed = append(e.observed, g)
	case "fallback":
		// One single-member balancer per member, each falling back to the
		// next. The random strategy skips members the observatory reports
		// dead and treats unprobed ones as alive, so the first member is
		// preferred from the start.
		for i, m := range members {
			b := balancer{Tag: g.Name, Selector: []string{m}, Strategy: strategy{"random"}}
			if i > 0 {
				b.Tag = fallbackName(g.Name, i+1)
			}
			if i+1 < len(members) {
				next := fallbackName(g.Name, i+2)
				e.loopback(next)
				b.FallbackTag = e.tags[next]
			}
			e.balancers = append(e.balancers, b)
		}
		e.observed = append(e.observed, g)
	}
}

// loopback emits an outbound that hands traffic to the balancer of the same name.
func (e *encoder) loopback(name string) {
	in := groupInPrefix + name
	e.outbounds = append(e.outbounds, outbound{Tag: e.tags[name], Protocol: "loopback", Settings: loopbackSettings{InboundTag: in}})
	e.dispatch = append(e.dispatch, rule{InboundTag: []string{in}, BalancerTag: name})
}

// target fills in where a rule sends traffic.
func (e *encoder) target(r *rule, name string) {
	if _, ok := e.groups[name]; ok {
		r.BalancerTag = name
	} else {
		r.OutboundTag = e.tags[name]
	}
}

func (e *encoder) rules() []rule {
	if e.r.Settings.Mode != "rule" {
		return nil // global and direct only use the default route
	}
	var out []rule
	for i, r := range e.r.Rules {
		var xs []rule
		switch r.Match {
		case route.MatchProcessName, route.MatchProcessPath:
			xs = []rule{{Process: []string{r.Value}}}
		case route.MatchDomain:
			xs = []rule{{Domain: []string{"full:" + r.Value}}}
		case route.MatchDomainSuffix:
			xs = []rule{{Domain: []string{"domain:" + r.Value}}}
		case route.MatchDomainKeyword:
			xs = []rule{{Domain: []string{"keyword:" + r.Value}}}
		case route.MatchIPCIDR:
			xs = []rule{{IP: []string{r.Value}}}
		case route.MatchRuleSet:
			xs = e.listRules(r)
		case route.MatchDstPort:
			xs = []rule{{Port: r.Value}}
		case route.MatchNetwork:
			xs = []rule{{Network: r.Value}}
		case route.MatchRaw:
			if r.Origin.Imported {
				continue // reported by backend.Check
			}
			e.d.Errorf(r.Origin.Pos, "xray 不支持 clash 原始规则")
			continue
		case route.MatchFinal:
			continue // the default route is the first outbound
		default:
			e.d.Errorf(r.Origin.Pos, "xray 不支持这种规则（%s）", r.Origin.Key)
			continue
		}
		for k, x := range xs {
			x.RuleTag = ruleTag(i, k, r.Origin.Key)
			e.target(&x, r.Target)
			out = append(out, x)
			data, _ := json.Marshal(x)
			e.manifest.Rules = append(e.manifest.Rules, backend.ManifestRule{
				Index:   i,
				Rule:    string(data),
				Tag:     x.RuleTag,
				Tier:    r.Origin.Tier.String(),
				Key:     r.Origin.Key,
				Source:  r.Origin.Pos.String(),
				Builtin: r.Origin.Builtin,
			})
		}
	}
	return out
}

// ruleTag names a rule after the compiled rule it came from. xray logs the
// tag of the rule each connection matched, which is how nautilus explains
// connections, and the key keeps xray's own log readable.
func ruleTag(index, part int, key string) string {
	key = strings.NewReplacer("[", "", "]", "").Replace(key)
	if part == 0 {
		return fmt.Sprintf("#%d %s", index, key)
	}
	return fmt.Sprintf("#%d.%d %s", index, part+1, key)
}

// RuleIndex reads the compiled rule index back from a rule tag.
func RuleIndex(tag string) (int, bool) {
	rest, ok := strings.CutPrefix(tag, "#")
	if !ok {
		return 0, false
	}
	end := strings.IndexAny(rest, ". ")
	if end < 0 {
		end = len(rest)
	}
	i, err := strconv.Atoi(rest[:end])
	return i, err == nil
}

// ProbeTag names the i-th probe: an inbound, a rule and a balancer whose
// target nautilus overrides to measure the delay through any outbound.
func ProbeTag(i int) string {
	return compile.HopSep + "probe" + compile.HopSep + strconv.Itoa(i+1)
}

// listRules turns a rule list into xray rules. geosite/geoip categories
// come from xray's geodata files; other lists are inlined.
func (e *encoder) listRules(r route.Rule) []rule {
	var p route.Provider
	for _, q := range e.r.Providers {
		if q.Name == r.Value {
			p = q
		}
	}
	switch p.Geo {
	case "geosite":
		return []rule{{Domain: []string{"geosite:" + p.Category}}}
	case "geoip":
		return []rule{{IP: []string{"geoip:" + p.Category}}}
	}
	if p.Format == "mrs" {
		e.listProblem(r, "xray 无法读取 mrs 格式的规则列表 %s，请改用 yaml 或 text 格式的版本", p.URL)
		return nil
	}
	var entries []lists.Entry
	var skipped []string
	var err error
	switch {
	case p.URL == "":
		entries, skipped, err = lists.Parse([]byte(strings.Join(p.Payload, "\n")), "text", p.Behavior)
	case e.opts.Lists == nil:
		e.listProblem(r, "xray 需要先下载规则列表 %s", p.URL)
		return nil
	default:
		entries, skipped, err = e.opts.Lists(p)
	}
	if p.Format == "autoproxy" {
		entries = lists.Select(entries, p.Exceptions)
		if len(entries) == 0 && err == nil {
			return nil // e.g. a list without "@@" exceptions
		}
	}
	if err != nil {
		e.listProblem(r, "%v", err)
		return nil
	}
	if len(skipped) > 0 && !p.Exceptions {
		e.d.Warnf(r.Origin.Pos, "规则列表 %s 中有 %d 条 xray 无法表达的规则，已跳过（例如 %q）", p.URL, len(skipped), skipped[0])
	}
	return entryRules(entries)
}

// listProblem reports a list xray cannot use. For a list the user wrote it
// is an error; for one a subscription brought along, the list is skipped.
func (e *encoder) listProblem(r route.Rule, format string, args ...any) {
	if r.Origin.Imported {
		e.d.Warnf(r.Origin.Pos, "已跳过订阅 %q 的一个规则集："+format, append([]any{r.Origin.Key}, args...)...)
		return
	}
	e.d.Errorf(r.Origin.Pos, format, args...)
}

// entryRules groups list entries by the field xray matches them on. Fields
// within one xray rule are ANDed, so each field gets its own rule.
func entryRules(entries []lists.Entry) []rule {
	var domains, ips, procs, ports, networks []string
	for _, en := range entries {
		switch en.Kind {
		case lists.Domain:
			domains = append(domains, "full:"+en.Value)
		case lists.DomainSuffix:
			domains = append(domains, "domain:"+en.Value)
		case lists.DomainKeyword:
			domains = append(domains, "keyword:"+en.Value)
		case lists.DomainRegex:
			domains = append(domains, "regexp:"+en.Value)
		case lists.GeoSite:
			domains = append(domains, "geosite:"+en.Value)
		case lists.IPCIDR:
			ips = append(ips, en.Value)
		case lists.GeoIP:
			ips = append(ips, "geoip:"+en.Value)
		case lists.ProcessName, lists.ProcessPath:
			procs = append(procs, en.Value)
		case lists.DstPort:
			ports = append(ports, en.Value)
		case lists.Network:
			networks = append(networks, en.Value)
		}
	}
	var out []rule
	if domains != nil {
		out = append(out, rule{Domain: domains})
	}
	if ips != nil {
		out = append(out, rule{IP: ips})
	}
	if procs != nil {
		out = append(out, rule{Process: procs})
	}
	if ports != nil {
		out = append(out, rule{Port: strings.Join(ports, ",")})
	}
	if networks != nil {
		out = append(out, rule{Network: strings.Join(networks, ",")})
	}
	return out
}

// defaultFirst moves the default route's outbound to the front: xray sends
// traffic no rule matched to the first outbound.
func (e *encoder) defaultFirst() []outbound {
	def := "DIRECT"
	switch e.r.Settings.Mode {
	case "global":
		def = compile.GlobalGroup
	case "rule":
		for _, r := range e.r.Rules {
			if r.Match == route.MatchFinal {
				def = r.Target
			}
		}
	}
	out := slices.Clone(e.outbounds)
	i := slices.IndexFunc(out, func(o outbound) bool { return o.Tag == e.tags[def] })
	if i > 0 {
		first := out[i]
		out = append(out[:i], out[i+1:]...)
		out = append([]outbound{first}, out...)
	}
	return out
}

func (e *encoder) mixedInbound() inbound {
	s := e.r.Settings
	listen := "127.0.0.1"
	if s.AllowLAN {
		listen = cmp.Or(s.BindAddress, "0.0.0.0")
	}
	return inbound{
		Tag:      inMixed,
		Protocol: "mixed",
		Listen:   listen,
		Port:     s.MixedPort,
		Settings: mixedSettings{UDP: true},
		// Route-only sniffing lets domain rules apply to clients that
		// connect by IP, without changing where the connection goes.
		Sniffing: &sniffing{Enabled: true, DestOverride: []string{"http", "tls", "quic"}, RouteOnly: true},
	}
}

// observatory probes every member of groups that pick by health. xray has
// a single observatory, so the first group's URL and the shortest interval win.
func (e *encoder) observatory() *observatory {
	if len(e.observed) == 0 {
		return nil
	}
	o := &observatory{ProbeURL: e.observed[0].URL, EnableConcurrency: true}
	interval := e.observed[0].Interval
	for _, g := range e.observed {
		for _, m := range g.Members {
			if tag := e.tags[m]; !slices.Contains(o.SubjectSelector, tag) {
				o.SubjectSelector = append(o.SubjectSelector, tag)
			}
		}
		if g.URL != o.ProbeURL {
			e.d.Warnf(g.Pos, "出口组 %q：xray 只能用一个测速地址，统一使用 %s", g.Name, o.ProbeURL)
		}
		interval = min(interval, g.Interval)
	}
	o.ProbeInterval = fmt.Sprintf("%ds", interval)
	return o
}

// localDNS sends encrypted DNS queries directly. xray routes DoH queries
// through the routing rules unless asked not to, while mihomo sends its
// nameserver queries directly; this keeps the backends alike.
func localDNS(servers []string) []string {
	out := make([]string, len(servers))
	for i, s := range servers {
		out[i] = s
		for _, scheme := range []string{"https://", "tcp://", "quic://"} {
			if rest, ok := strings.CutPrefix(s, scheme); ok {
				out[i] = strings.TrimSuffix(scheme, "://") + "+local://" + rest
			}
		}
	}
	return out
}

func logLevel(l string) string {
	if l == "silent" {
		return "none"
	}
	return l
}
