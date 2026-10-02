package compile

import (
	"slices"
	"strconv"
	"strings"

	"github.com/xiongnemo/conch/internal/model"
)

func (c *compiler) resolveChains() {
	for _, ch := range c.res.Chains {
		if !c.checkHops(ch) {
			continue
		}
		if path, ok := c.flatten(ch, nil); ok {
			ch.Path = path
		}
	}
}

// checkHops validates each hop of a chain on its own.
func (c *compiler) checkHops(ch *Chain) bool {
	if len(ch.Hops) < 2 {
		c.d.Errorf(ch.Pos, "链 %q 至少需要两跳；只走一个出口时，直接写那个出口的名字即可", ch.Name)
		return false
	}
	ok := true
	for i, h := range ch.Hops {
		e := c.names[h]
		switch {
		case e == nil:
			c.d.Errorf(ch.Pos, "链 %q 的第 %d 跳 %q 不存在", ch.Name, i+1, h)
			ok = false
		case e.kind == kBuiltin:
			c.d.Errorf(ch.Pos, "链 %q 的第 %d 跳不能是 %s", ch.Name, i+1, h)
			ok = false
		case i > 0 && e.kind == kGroup:
			// Its members are copied to dial through the hop before, so
			// they must be nodes.
			for _, m := range e.group.Members {
				if c.names[m] == nil || c.names[m].kind != kNode {
					c.d.Errorf(ch.Pos, "链 %q 的第 %d 跳是出口组 %q，但它的成员 %q 不是节点；放在第一跳以后的出口组只能由节点组成", ch.Name, i+1, h, m)
					ok = false
					break
				}
			}
		}
	}
	return ok
}

// flatten returns the chain's hops with any chain appearing after the first
// hop replaced by its own hops. The first hop is kept as a reference.
func (c *compiler) flatten(ch *Chain, stack []*Chain) ([]string, bool) {
	if slices.Contains(stack, ch) {
		c.d.Errorf(ch.Pos, "链 %q 嵌套引用了它自己", ch.Name)
		return nil, false
	}
	path := []string{ch.Hops[0]}
	for i, h := range ch.Hops[1:] {
		e := c.names[h]
		if e.kind != kChain {
			path = append(path, h)
			continue
		}
		inner := e.chain
		if !c.checkHops(inner) {
			return nil, false
		}
		if first := c.names[inner.Hops[0]]; first.kind != kNode {
			c.d.Errorf(ch.Pos, "链 %q 的第 %d 跳是链 %q，但它的第一跳 %q 不是节点；放在后面位置的链只能由节点组成", ch.Name, i+2, inner.Name, inner.Hops[0])
			return nil, false
		}
		sub, ok := c.flatten(inner, append(stack, ch))
		if !ok {
			return nil, false
		}
		path = append(path, sub...)
	}
	return path, true
}

// checkCycles rejects loops through group members, chain entry hops and
// hand-written dialer-proxy settings. mihomo only detects some of these and
// otherwise recurses at connection time.
func (c *compiler) checkCycles() {
	edges := func(name string) []string {
		e := c.names[name]
		switch e.kind {
		case kGroup:
			return e.group.Members
		case kChain:
			if e.chain.Path != nil {
				return e.chain.Path[:1]
			}
		case kNode:
			if up := sanitize(e.node.View.DialerProxy); up != "" {
				if c.names[up] == nil {
					c.d.Errorf(e.pos, "节点 %q 的 dialer-proxy 指向不存在的 %q", name, up)
					return nil
				}
				return []string{up}
			}
		}
		return nil
	}
	state := map[string]int{} // 1 = on stack, 2 = done
	var stack []string
	var visit func(string) bool
	visit = func(n string) bool {
		switch state[n] {
		case 1:
			loop := append(slices.Clone(stack[slices.Index(stack, n):]), n)
			c.d.Errorf(c.names[n].pos, "出现了循环引用：%s", strings.Join(loop, " → "))
			return false
		case 2:
			return true
		}
		state[n] = 1
		stack = append(stack, n)
		for _, m := range edges(n) {
			if !visit(m) {
				return false
			}
		}
		stack = stack[:len(stack)-1]
		state[n] = 2
		return true
	}
	var roots []string
	for _, g := range c.res.Groups {
		roots = append(roots, g.Name)
	}
	for _, ch := range c.res.Chains {
		roots = append(roots, ch.Name)
	}
	for _, p := range c.res.Proxies {
		roots = append(roots, p.Name)
	}
	for _, r := range roots {
		if !visit(r) {
			return
		}
	}
}

// expandChains emits one proxy per hop after the first. Each dials through
// the previous hop; the last one carries the chain's name, so routes and
// latency tests that target the chain cover the whole path.
//
// A group after the first hop is copied: each member gets a copy dialing
// through the previous hop, and a copy of the group picks among those.
func (c *compiler) expandChains() {
	for _, ch := range c.res.Chains {
		prev := ch.Path[0]
		for i := 1; i < len(ch.Path); i++ {
			last := i == len(ch.Path)-1
			e := c.names[ch.Path[i]]
			if e.kind == kGroup {
				prev = c.copyGroup(ch, i, e.group, prev, last)
				continue
			}
			p := c.hopProxy(ch, i, e.node, prev)
			if last {
				p.Name, p.Kind = ch.Name, ProxyChainExit
			}
			c.res.Proxies = append(c.res.Proxies, p)
			prev = p.Name
		}
	}
}

func (c *compiler) hopProxy(ch *Chain, i int, node *model.Node, prev string) *Proxy {
	if node.View.DialerProxy != "" {
		c.d.Warnf(node.Pos, "节点 %q 自带 dialer-proxy，在链 %q 中会改为经由 %q 连接", node.Name, ch.Name, prev)
	}
	return &Proxy{Name: ch.Name + HopSep + strconv.Itoa(i) + HopSep + node.Name, Node: node, Upstream: prev, Kind: ProxyChainHop, Chain: ch.Name, Hop: i}
}

// copyGroup emits group orig as hop i of chain ch and returns the copy's name.
func (c *compiler) copyGroup(ch *Chain, i int, orig *Group, prev string, last bool) string {
	cp := *orig
	cp.Name, cp.Chain, cp.Hop, cp.Follows, cp.Members, cp.Selected = ch.Name+HopSep+strconv.Itoa(i)+HopSep+orig.Name, ch.Name, i, orig.Name, nil, ""
	if last {
		cp.Name = ch.Name
	}
	for _, m := range orig.Members {
		p := c.hopProxy(ch, i, c.names[m].node, prev)
		c.res.Proxies = append(c.res.Proxies, p)
		cp.Members = append(cp.Members, p.Name)
	}
	if cp.Type == "select" {
		cp.Selected = c.res.FollowingMember(&cp, orig.Selected)
	}
	c.res.Groups = append(c.res.Groups, &cp)
	return cp.Name
}

// Protocols that run over UDP (QUIC or WireGuard) need the previous hop to
// relay datagrams even for TCP traffic.
var udpTransport = map[string]bool{"hysteria": true, "hysteria2": true, "tuic": true, "wireguard": true}

func relaysUDP(n *model.Node) bool {
	t := strings.ToLower(n.View.Type)
	switch {
	case udpTransport[t]:
		return true
	case t == "http":
		return false
	default:
		return n.View.UDP != nil && *n.View.UDP
	}
}

func (c *compiler) checkUDP() {
	for _, ch := range c.res.Chains {
		for i := 1; i < len(ch.Path); i++ {
			for _, node := range c.leaves(ch.Path[i]) {
				if !udpTransport[strings.ToLower(node.View.Type)] {
					continue
				}
				var bad []string
				for _, leaf := range c.leaves(ch.Path[i-1]) {
					if !relaysUDP(leaf) {
						bad = append(bad, leaf.Name)
					}
				}
				if len(bad) > 0 {
					c.d.Warnf(ch.Pos, "链 %q 的第 %d 跳 %q 是基于 UDP 的 %s，需要前一跳能转发 UDP；但 %s 没有开启 udp: true 或不支持 UDP，这条链很可能连不通",
						ch.Name, i+1, node.Name, node.View.Type, strings.Join(bad, "、"))
				}
			}
		}
	}
}

// leaves lists the nodes that may end up carrying traffic for an outbound.
func (c *compiler) leaves(name string) []*model.Node {
	seen := map[string]bool{}
	var out []*model.Node
	var walk func(string)
	walk = func(n string) {
		if seen[n] {
			return
		}
		seen[n] = true
		e := c.names[n]
		switch e.kind {
		case kNode:
			out = append(out, e.node)
		case kGroup:
			for _, m := range e.group.Members {
				walk(m)
			}
		case kChain:
			for _, h := range e.chain.Path {
				walk(h)
			}
		}
	}
	walk(name)
	return out
}

// RelaysUDP reports whether UDP traffic sent to an outbound gets through:
// every node that may carry it, on every hop, must relay UDP.
func (r *Result) RelaysUDP(name string) bool {
	seen := map[string]bool{}
	var walk func(string) bool
	walk = func(n string) bool {
		if seen[n] {
			return true
		}
		seen[n] = true
		switch n {
		case "DIRECT":
			return true
		case "REJECT", "REJECT-DROP":
			return false
		}
		for _, g := range r.Groups {
			if g.Name == n {
				return len(g.Members) > 0 && !slices.ContainsFunc(g.Members, func(m string) bool { return !walk(m) })
			}
		}
		for _, c := range r.Chains {
			if c.Name == n {
				return !slices.ContainsFunc(c.Path, func(h string) bool { return !walk(h) })
			}
		}
		for _, p := range r.Proxies {
			if p.Name == n && p.Kind == ProxyNode {
				return relaysUDP(p.Node)
			}
		}
		return false
	}
	return walk(name)
}
