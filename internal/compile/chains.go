package compile

import (
	"slices"
	"strconv"
	"strings"

	"nautilus/internal/model"
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
			c.d.Errorf(ch.Pos, "链 %q 的第 %d 跳 %q 是出口组；目前出口组只能放在链的第一跳", ch.Name, i+1, h)
			ok = false
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
func (c *compiler) expandChains() {
	for _, ch := range c.res.Chains {
		prev := ch.Path[0]
		for i := 1; i < len(ch.Path); i++ {
			node := c.names[ch.Path[i]].node
			p := &Proxy{Name: ch.Name, Node: node, Upstream: prev, Kind: ProxyChainExit, Chain: ch.Name, Hop: i}
			if i < len(ch.Path)-1 {
				p.Name = ch.Name + HopSep + strconv.Itoa(i) + HopSep + node.Name
				p.Kind = ProxyChainHop
			}
			if node.View.DialerProxy != "" {
				c.d.Warnf(node.Pos, "节点 %q 自带 dialer-proxy，在链 %q 中会改为经由 %q 连接", node.Name, ch.Name, prev)
			}
			c.res.Proxies = append(c.res.Proxies, p)
			prev = p.Name
		}
	}
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
			node := c.names[ch.Path[i]].node
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
