package tui

import (
	"context"
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"

	"nautilus/internal/daemon"
)

type (
	groupItem  struct{ name string }
	memberItem struct{ group, member string }
	chainItem  struct{ name string }
	nodeItem   struct{ name string }
)

func (m *Model) outbound(name string) *daemon.Outbound {
	for i := range m.outbounds {
		if m.outbounds[i].Name == name {
			return &m.outbounds[i]
		}
	}
	return nil
}

// current is the member a group uses now, as far as the daemon knows.
func current(g *daemon.Outbound) string {
	if g.Now != "" {
		return g.Now
	}
	return g.Selected
}

func (m *Model) delayCell(name string) string {
	d, ok := m.delays[name]
	switch {
	case !ok:
		return ""
	case d.pending:
		return muted.Render("测速中…")
	}
	return delayText(d.ms, d.err)
}

// hopLabel shows a group hop with the member it uses: 香港自动[HK 03].
func (m *Model) hopLabel(name string) string {
	if o := m.outbound(name); o != nil && o.Kind == "group" && current(o) != "" {
		return name + muted.Render("["+current(o)+"]")
	}
	return name
}

func (m *Model) chainPath(c daemon.Outbound) string {
	d := m.delays[c.Name]
	var parts []string
	for i, hop := range c.Hops {
		part := m.hopLabel(hop)
		if i < len(d.hops) && !d.pending {
			part += " " + delayText(d.hops[i].Delay, d.hops[i].Error)
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, muted.Render(" → "))
}

func (m *Model) outboundRows(w int) []row {
	if len(m.outbounds) == 0 {
		return []row{{text: muted.Render("还没有出口信息")}}
	}
	var groups, chains, nodes []daemon.Outbound
	for _, o := range m.outbounds {
		switch o.Kind {
		case "group":
			groups = append(groups, o)
		case "chain":
			chains = append(chains, o)
		case "node":
			nodes = append(nodes, o)
		}
	}
	udp := accent.Render(" UDP")
	var rows []row
	if len(groups) > 0 {
		rows = append(rows, title("出口组"))
	}
	for _, g := range groups {
		open := m.expanded[g.Name]
		mark := "▸ "
		if open {
			mark = "▾ "
		}
		desc := kindNames[g.Type]
		if now := current(&g); now != "" {
			desc += " · 当前 " + now
		}
		left := mark + bold.Render(g.Name) + "  " + muted.Render(desc)
		rows = append(rows, row{text: spread(left, muted.Render(fmt.Sprintf("%d 个成员", len(g.Members))), w), item: groupItem{g.Name}})
		if !open {
			continue
		}
		for _, member := range g.Members {
			mark := "    "
			if member == current(&g) {
				mark = "  " + accent.Render("●") + " "
			}
			rows = append(rows, row{text: spread("  "+mark+member, m.delayCell(member), w), item: memberItem{g.Name, member}})
		}
	}
	if len(chains) > 0 {
		rows = append(rows, blank(), title("链"))
	}
	for _, c := range chains {
		left := "  " + bold.Render(c.Name) + "  " + m.chainPath(c)
		if c.UDP {
			left += udp
		}
		rows = append(rows, row{text: spread(left, m.delayCell(c.Name), w), item: chainItem{c.Name}})
	}
	if len(nodes) > 0 {
		rows = append(rows, blank(), title("节点"))
	}
	for _, n := range nodes {
		left := "  " + n.Name + "  " + muted.Render(n.Type+" · "+n.Server)
		if n.UDP {
			left += udp
		}
		rows = append(rows, row{text: spread(left, m.delayCell(n.Name), w), item: nodeItem{n.Name}})
	}
	return rows
}

func (m *Model) outboundsKey(key string, item any) tea.Cmd {
	switch key {
	case "enter", "space", "right", "left", "l", "h":
		switch it := item.(type) {
		case groupItem:
			open := !m.expanded[it.name]
			if key == "right" || key == "l" {
				open = true
			} else if key == "left" || key == "h" {
				open = false
			}
			m.expanded[it.name] = open
		case memberItem:
			if key == "left" || key == "h" {
				m.expanded[it.group] = false
				m.lists[pageOutbounds].move(m.rows(), -m.memberIndex(it)-1)
				return nil
			}
			if key != "enter" && key != "space" {
				return nil
			}
			g := m.outbound(it.group)
			if g == nil {
				return nil
			}
			if g.Type != "select" {
				m.note(fmt.Sprintf("%s 是%s出口组，由内核自动挑选成员", it.group, kindNames[g.Type]), true)
				return nil
			}
			return m.do(fmt.Sprintf("%s 现在使用 %s", it.group, it.member), func(ctx context.Context) error {
				return m.c.Select(ctx, it.group, it.member)
			})
		}
	case "t":
		switch it := item.(type) {
		case groupItem:
			if g := m.outbound(it.name); g != nil {
				return m.testDelay(g.Members...)
			}
		case memberItem:
			return m.testDelay(it.member)
		case chainItem:
			return m.testDelay(it.name)
		case nodeItem:
			return m.testDelay(it.name)
		}
	}
	return nil
}

func (m *Model) memberIndex(it memberItem) int {
	if g := m.outbound(it.group); g != nil {
		for i, member := range g.Members {
			if member == it.member {
				return i
			}
		}
	}
	return 0
}
