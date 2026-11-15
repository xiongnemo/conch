// Package subscription fetches, caches and parses proxy subscriptions, and
// merges what they provide into a profile.
package subscription

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/xiongnemo/conch/internal/linkparse"
	"github.com/xiongnemo/conch/internal/model"
	"github.com/xiongnemo/conch/internal/proto"
	"github.com/xiongnemo/conch/internal/rx"
)

// Snapshot is a parsed subscription, before it is merged into a profile.
type Snapshot struct {
	Nodes         []*yaml.Node // Clash proxy mappings, names as provided
	Groups        []*yaml.Node // Clash proxy-group mappings
	Rules         []string
	RuleProviders map[string]*model.RuleProvider
	// Providers lists the node names each proxy-provider contributed, for
	// groups that use them.
	Providers map[string][]string
	Warnings  []string
}

// FetchFunc downloads a proxy-provider referenced by a subscription.
type FetchFunc func(url string) ([]byte, error)

// Parse decodes a subscription body: a Clash/mihomo config, or a list of
// share links, optionally base64-encoded.
func Parse(body []byte, fetch FetchFunc) (*Snapshot, error) {
	body = bytes.TrimPrefix(bytes.TrimSpace(body), []byte("\ufeff"))
	if len(body) == 0 {
		return nil, fmt.Errorf("订阅内容是空的")
	}
	if bytes.HasPrefix(bytes.TrimSpace(body), []byte("<")) {
		return nil, fmt.Errorf("订阅返回的是网页而不是订阅内容")
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(body, &doc); err == nil && len(doc.Content) > 0 && doc.Content[0].Kind == yaml.MappingNode {
		root := doc.Content[0]
		if model.Lookup(root, "proxies") != nil || model.Lookup(root, "proxy-providers") != nil {
			return parseClash(root, fetch)
		}
	}
	return parseLinks(body)
}

func parseLinks(body []byte) (*Snapshot, error) {
	text := string(body)
	if !strings.Contains(text, "://") {
		decoded, err := linkparse.DecodeBase64(strings.Join(strings.Fields(text), ""))
		if err != nil {
			return nil, fmt.Errorf("无法识别的订阅格式（不是 Clash 配置，也不是分享链接）")
		}
		text = string(decoded)
	}
	s := &Snapshot{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, spec, err := linkparse.Parse(line)
		if err != nil {
			s.Warnings = append(s.Warnings, err.Error())
			continue
		}
		if len(spec.Unknown) > 0 {
			s.Warnings = append(s.Warnings, fmt.Sprintf("节点 %q 的这些参数无法识别，已忽略：%s", name, strings.Join(spec.Unknown, "、")))
		}
		s.Nodes = append(s.Nodes, proto.ToClash(name, spec))
	}
	if len(s.Nodes) == 0 {
		return nil, noNodes(s.Warnings)
	}
	return s, nil
}

// maxNodes bounds the YAML nodes a subscription may expand to: real ones
// have tens of thousands, a malicious one could have billions.
const maxNodes = 1 << 19

// flattener copies a subscription's YAML within one budget for the whole
// document.
type flattener struct {
	left int
	err  error
}

func (f *flattener) flat(n *yaml.Node) *yaml.Node {
	if f.err != nil {
		return &yaml.Node{Kind: yaml.MappingNode}
	}
	out, err := model.FlattenWithin(n, &f.left)
	if err != nil {
		f.err = err
		return &yaml.Node{Kind: yaml.MappingNode}
	}
	return out
}

func parseClash(root *yaml.Node, fetch FetchFunc) (*Snapshot, error) {
	s := &Snapshot{RuleProviders: map[string]*model.RuleProvider{}, Providers: map[string][]string{}}
	f := &flattener{left: maxNodes}
	if n := model.Lookup(root, "proxies"); n != nil && n.Kind == yaml.SequenceNode {
		for _, p := range n.Content {
			if p.Kind == yaml.MappingNode {
				s.Nodes = append(s.Nodes, f.flat(p))
			}
		}
	}
	if n := model.Lookup(root, "proxy-providers"); n != nil && n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			s.addProvider(n.Content[i].Value, f.flat(n.Content[i+1]), fetch, f)
		}
	}
	if n := model.Lookup(root, "proxy-groups"); n != nil && n.Kind == yaml.SequenceNode {
		for _, g := range n.Content {
			if g.Kind == yaml.MappingNode {
				s.Groups = append(s.Groups, f.flat(g))
			}
		}
	}
	if n := model.Lookup(root, "rules"); n != nil && n.Kind == yaml.SequenceNode {
		for _, r := range n.Content {
			if v := model.WeakString(r); v != "" {
				s.Rules = append(s.Rules, v)
			}
		}
	}
	if n := model.Lookup(root, "rule-providers"); n != nil && n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			name, m := n.Content[i].Value, n.Content[i+1]
			rp, err := ruleProvider(name, m)
			if err != nil {
				s.Warnings = append(s.Warnings, err.Error())
				continue
			}
			s.RuleProviders[name] = rp
		}
	}
	if f.err != nil {
		return nil, fmt.Errorf("订阅内容有问题，已拒绝：%w", f.err)
	}
	if len(s.Nodes) == 0 {
		return nil, noNodes(s.Warnings)
	}
	return s, nil
}

// addProvider inlines a proxy-provider: dialer-proxy cannot point at
// provider nodes, and conch needs to see every node anyway.
func (s *Snapshot) addProvider(name string, m *yaml.Node, fetch FetchFunc, f *flattener) {
	str := func(k string) string { return model.WeakString(model.Lookup(m, k)) }
	var nodes []*yaml.Node
	switch typ := strings.ToLower(str("type")); typ {
	case "http":
		if fetch == nil {
			s.Warnings = append(s.Warnings, fmt.Sprintf("没有下载 proxy-provider %q", name))
			return
		}
		body, err := fetch(str("url"))
		if err == nil {
			var sub *Snapshot
			if sub, err = Parse(body, nil); err == nil {
				nodes = sub.Nodes
				s.Warnings = append(s.Warnings, sub.Warnings...)
			}
		}
		if err != nil {
			s.Warnings = append(s.Warnings, fmt.Sprintf("proxy-provider %q：%v", name, err))
			return
		}
	case "inline":
		if p := model.Lookup(m, "payload"); p != nil && p.Kind == yaml.SequenceNode {
			for _, n := range p.Content {
				nodes = append(nodes, f.flat(n))
			}
		}
	default:
		s.Warnings = append(s.Warnings, fmt.Sprintf("proxy-provider %q 的类型 %q 无法导入", name, typ))
		return
	}

	// As mihomo does (adapter/provider): types and names filtered on the
	// names as given, then the provider's dialer-proxy, then override.
	keep, drop := compileOrWarn(s, str("filter")), compileOrWarn(s, str("exclude-filter"))
	var excludeTypes []string
	for t := range strings.SplitSeq(str("exclude-type"), "|") {
		if t = strings.TrimSpace(t); t != "" {
			excludeTypes = append(excludeTypes, strings.ToLower(t))
		}
	}
	over := model.Lookup(m, "override")
	renames := s.proxyNameRules(name, over)
	if e := model.Lookup(over, "override-expr"); e != nil {
		s.Warnings = append(s.Warnings, fmt.Sprintf("proxy-provider %q 的 override-expr 是 mihomo 自己的表达式，conch 做不到，没有用", name))
	}
	seen := map[string]bool{}
	for _, n := range nodes {
		nodeName := model.WeakString(model.Lookup(n, "name"))
		typ := strings.ToLower(model.WeakString(model.Lookup(n, "type")))
		if slices.Contains(excludeTypes, typ) || (drop != nil && drop.MatchString(nodeName)) || (keep != nil && !keep.MatchString(nodeName)) || seen[nodeName] {
			continue
		}
		seen[nodeName] = true
		if dp := str("dialer-proxy"); dp != "" {
			model.SetKey(n, "dialer-proxy", model.Str(dp))
		}
		if over != nil && over.Kind == yaml.MappingNode {
			for _, key := range overrideKeys {
				if v := model.Lookup(over, key); v != nil {
					c := *v
					model.SetKey(n, key, &c)
				}
			}
			for _, r := range renames {
				nodeName = r.re.ReplaceAllString(nodeName, r.to)
			}
			nodeName = model.WeakString(model.Lookup(over, "additional-prefix")) + nodeName + model.WeakString(model.Lookup(over, "additional-suffix"))
		}
		model.SetKey(n, "name", model.Str(nodeName))
		s.Nodes = append(s.Nodes, n)
		s.Providers[name] = append(s.Providers[name], nodeName)
	}
}

// overrideKeys are the node settings a proxy-provider's override sets on
// every node it has, as in mihomo.
var overrideKeys = []string{"tfo", "mptcp", "udp", "udp-over-tcp", "up", "down", "dialer-proxy",
	"skip-cert-verify", "name-cert-verify", "interface-name", "routing-mark", "ip-version"}

type rename struct {
	re *rx.Regexp
	to string
}

// proxyNameRules reads override.proxy-name: patterns replaced in names,
// .NET-style as mihomo's; ones that cannot be read are reported.
func (s *Snapshot) proxyNameRules(provider string, over *yaml.Node) []rename {
	list := model.Lookup(over, "proxy-name")
	if list == nil || list.Kind != yaml.SequenceNode {
		return nil
	}
	var out []rename
	for _, item := range list.Content {
		pattern := model.WeakString(model.Lookup(item, "pattern"))
		re, err := rx.Compile(pattern)
		if err != nil {
			s.Warnings = append(s.Warnings, fmt.Sprintf("proxy-provider %q 的 proxy-name 规则 %q 不是有效的正则表达式（%v），没有用", provider, pattern, err))
			continue
		}
		out = append(out, rename{re, model.WeakString(model.Lookup(item, "target"))})
	}
	return out
}

func ruleProvider(name string, m *yaml.Node) (*model.RuleProvider, error) {
	str := func(k string) string { return strings.ToLower(model.WeakString(model.Lookup(m, k))) }
	rp := &model.RuleProvider{Name: name, Behavior: str("behavior"), Format: str("format")}
	if rp.Behavior == "" {
		rp.Behavior = "classical"
	}
	switch str("type") {
	case "http":
		rp.URL = model.WeakString(model.Lookup(m, "url"))
		if rp.Format == "" {
			rp.Format = "yaml" // mihomo's default
		}
	case "inline":
		if p := model.Lookup(m, "payload"); p != nil && p.Kind == yaml.SequenceNode {
			for _, n := range p.Content {
				rp.Payload = append(rp.Payload, model.WeakString(n))
			}
		}
	default:
		return nil, fmt.Errorf("规则集 %q 的类型 %q 无法导入", name, str("type"))
	}
	return rp, nil
}

// compileOrWarn compiles a provider's filter, several expressions
// separated by backticks as mihomo has them.
func compileOrWarn(s *Snapshot, expr string) rx.List {
	if expr == "" {
		return nil
	}
	re, err := rx.CompileList(expr)
	if err != nil {
		s.Warnings = append(s.Warnings, fmt.Sprintf("无法使用正则表达式 %q（%v），已忽略这个过滤条件", expr, err))
		return nil
	}
	return re
}

// noNodes is the error for content without a usable node, with the first
// reason something was skipped.
func noNodes(warnings []string) error {
	switch len(warnings) {
	case 0:
		return fmt.Errorf("订阅里没有可用的节点")
	case 1:
		return fmt.Errorf("订阅里没有可用的节点：%s", warnings[0])
	}
	return fmt.Errorf("订阅里没有可用的节点：%s（另有 %d 个问题）", warnings[0], len(warnings)-1)
}
