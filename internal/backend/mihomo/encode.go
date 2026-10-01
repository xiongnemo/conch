// Package mihomo encodes compiled profiles into mihomo configuration.
package mihomo

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"nautilus/internal/backend"
	"nautilus/internal/compile"
	"nautilus/internal/model"
	"nautilus/internal/route"
)

type Backend struct{}

func (Backend) Name() string { return "mihomo" }

func (Backend) Capabilities() backend.Capabilities {
	return backend.Capabilities{ProcessMatch: true, KeywordMatch: true, RawClash: true, Chains: true}
}

// corsNobody is an origin no page can have. mihomo treats an empty
// allow-origins list as "allow every origin", so we must list something.
const corsNobody = "https://nautilus.invalid"

const providerInterval = 86400

var fakeIPFilter = []string{
	"+.lan", "+.local", "+.localhost", "+.home.arpa",
	"+.msftconnecttest.com", "+.msftncsi.com", "time.*.com", "ntp.*.com",
}

func (Backend) Encode(r *compile.Result, opts backend.Options) (*backend.Artifact, error) {
	s := r.Settings
	doc := newMap()
	doc.set("mixed-port", intNode(s.MixedPort))
	doc.set("allow-lan", boolNode(s.AllowLAN))
	if s.BindAddress != "" {
		doc.set("bind-address", str(s.BindAddress))
	}
	doc.set("mode", str(s.Mode))
	doc.set("log-level", str(s.LogLevel))

	if opts.ControllerUnix != "" {
		doc.set("external-controller-unix", str(opts.ControllerUnix))
	}
	if opts.ControllerPipe != "" {
		doc.set("external-controller-pipe", str(opts.ControllerPipe))
	}
	if opts.Controller != "" {
		doc.set("external-controller", str(opts.Controller))
		cors := newMap()
		cors.set("allow-origins", strSeq([]string{corsNobody}))
		cors.set("allow-private-network", boolNode(false))
		doc.set("external-controller-cors", cors.node)
	}

	profile := newMap()
	profile.set("store-selected", boolNode(true))
	doc.set("profile", profile.node)

	if s.DNS.Enable {
		doc.set("dns", dnsNode(s.DNS))
	}
	if s.TUN.Enable {
		doc.set("tun", tunNode(s.TUN))
	}

	proxies := &yaml.Node{Kind: yaml.SequenceNode}
	for _, p := range r.Proxies {
		proxies.Content = append(proxies.Content, proxyNode(p))
	}
	doc.set("proxies", proxies)

	groups := &yaml.Node{Kind: yaml.SequenceNode}
	for _, g := range r.Groups {
		groups.Content = append(groups.Content, groupNode(g))
	}
	doc.set("proxy-groups", groups)

	if len(r.Providers) > 0 {
		providers := newMap()
		for _, pv := range r.Providers {
			m := newMap()
			m.set("type", str("http"))
			m.set("behavior", str(pv.Behavior))
			m.set("format", str(pv.Format))
			m.set("url", str(pv.URL))
			m.set("interval", intNode(providerInterval))
			providers.set(pv.Name, m.node)
		}
		doc.set("rule-providers", providers.node)
	}

	manifest := &backend.Manifest{Backend: "mihomo", Proxies: backend.ProxyManifest(r)}
	rules := &yaml.Node{Kind: yaml.SequenceNode}
	for i, rule := range r.Rules {
		line, err := ruleLine(rule)
		if err != nil {
			return nil, err
		}
		rules.Content = append(rules.Content, str(line))
		manifest.Rules = append(manifest.Rules, backend.ManifestRule{
			Index:   i,
			Rule:    line,
			Tier:    rule.Origin.Tier.String(),
			Key:     rule.Origin.Key,
			Source:  rule.Origin.Pos.String(),
			Builtin: rule.Origin.Builtin,
		})
	}
	doc.set("rules", rules)

	root := &yaml.Node{
		Kind:        yaml.DocumentNode,
		HeadComment: "由 nautilus 生成，请不要手动修改；需要改动时请编辑 profile.yaml",
		Content:     []*yaml.Node{doc.node},
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return &backend.Artifact{Config: buf.Bytes(), Manifest: manifest}, nil
}

// proxyNode emits the node exactly as written, except for the name and
// dialer-proxy, which the compiler owns.
func proxyNode(p *compile.Proxy) *yaml.Node {
	m := model.Flatten(p.Node.Raw)
	blockStyle(m)
	model.SetKey(m, "name", str(p.Name))
	model.DeleteKey(m, "dialer-proxy")
	if p.Upstream != "" {
		m.Content = append(m.Content, str("dialer-proxy"), str(p.Upstream))
	}
	return m
}

func groupNode(g *compile.Group) *yaml.Node {
	m := newMap()
	m.set("name", str(g.Name))
	m.set("type", str(g.Type))
	m.set("proxies", strSeq(g.Members))
	if g.Type != "select" {
		m.set("url", str(g.URL))
		m.set("interval", intNode(g.Interval))
		if g.Tolerance > 0 {
			m.set("tolerance", intNode(g.Tolerance))
		}
		if g.Lazy != nil {
			m.set("lazy", boolNode(*g.Lazy))
		}
	}
	if g.Type == "load-balance" && g.Strategy != "" {
		m.set("strategy", str(g.Strategy))
	}
	return m.node
}

func dnsNode(d compile.DNSSettings) *yaml.Node {
	m := newMap()
	m.set("enable", boolNode(true))
	m.set("ipv6", boolNode(d.IPv6))
	m.set("enhanced-mode", str(d.Mode))
	if d.Mode == "fake-ip" {
		m.set("fake-ip-range", str("198.18.0.1/16"))
		m.set("fake-ip-filter", strSeq(fakeIPFilter))
	}
	m.set("nameserver", strSeq(d.Nameservers))
	return m.node
}

func tunNode(t compile.TUNSettings) *yaml.Node {
	m := newMap()
	m.set("enable", boolNode(true))
	m.set("stack", str(t.Stack))
	m.set("auto-route", boolNode(true))
	m.set("auto-detect-interface", boolNode(true))
	m.set("dns-hijack", strSeq([]string{"any:53", "tcp://any:53"}))
	m.set("strict-route", boolNode(t.StrictRoute))
	return m.node
}

func ruleLine(r route.Rule) (string, error) {
	var typ string
	switch r.Match {
	case route.MatchProcessPath:
		typ = "PROCESS-PATH"
	case route.MatchProcessName:
		typ = "PROCESS-NAME"
	case route.MatchDomain:
		typ = "DOMAIN"
	case route.MatchDomainSuffix:
		typ = "DOMAIN-SUFFIX"
	case route.MatchDomainKeyword:
		typ = "DOMAIN-KEYWORD"
	case route.MatchIPCIDR:
		typ = "IP-CIDR"
		if strings.Contains(r.Value, ":") {
			typ = "IP-CIDR6"
		}
		if r.NoResolve {
			return fmt.Sprintf("%s,%s,%s,no-resolve", typ, r.Value, r.Target), nil
		}
	case route.MatchRuleSet:
		typ = "RULE-SET"
	case route.MatchRaw:
		fields := append([]string(nil), r.RawFields...)
		fields[r.TargetField] = r.Target
		return strings.Join(fields, ","), nil
	case route.MatchFinal:
		return "MATCH," + r.Target, nil
	default:
		return "", fmt.Errorf("mihomo: 不支持的规则类型 %d", r.Match)
	}
	return typ + "," + r.Value + "," + r.Target, nil
}

// yaml node helpers

type mapBuilder struct{ node *yaml.Node }

func newMap() *mapBuilder { return &mapBuilder{node: &yaml.Node{Kind: yaml.MappingNode}} }

func (m *mapBuilder) set(key string, v *yaml.Node) {
	m.node.Content = append(m.node.Content, str(key), v)
}

func str(s string) *yaml.Node { return model.Str(s) }

func intNode(i int) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(i)}
}

func boolNode(b bool) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: strconv.FormatBool(b)}
}

func strSeq(ss []string) *yaml.Node {
	n := &yaml.Node{Kind: yaml.SequenceNode}
	for _, s := range ss {
		n.Content = append(n.Content, str(s))
	}
	return n
}

// blockStyle normalizes containers to block style so the output looks the
// same no matter how the user wrote their nodes.
func blockStyle(n *yaml.Node) {
	if n.Kind == yaml.MappingNode || n.Kind == yaml.SequenceNode {
		n.Style &^= yaml.FlowStyle
	}
	for _, c := range n.Content {
		blockStyle(c)
	}
}
