package tui

import (
	"context"
	"fmt"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"

	"github.com/xiongnemo/conch/internal/view"
)

type entryItem struct{ e view.Entry }

// searchBox asks where an address would go.
type searchBox struct {
	input textinput.Model
}

func newSearch() *searchBox {
	in := textinput.New()
	in.Prompt = "这个地址怎么走？ "
	return &searchBox{input: in}
}

func (s *searchBox) focused() bool { return s.input.Focused() }

func (s *searchBox) key(m *Model, k tea.KeyPressMsg) tea.Cmd {
	switch k.String() {
	case "esc":
		s.input.Blur()
		return nil
	case "enter":
		q := strings.TrimSpace(s.input.Value())
		if q == "" {
			return nil
		}
		s.input.Blur()
		return m.call(func(ctx context.Context) tea.Msg {
			v, err := m.c.Explain(ctx, q, "")
			return explainMsg{query: q, v: v, err: errText(err)}
		})
	}
	var cmd tea.Cmd
	s.input, cmd = s.input.Update(k)
	return cmd
}

func (m *Model) searchHeight() int { return 2 }

func (m *Model) searchView(w int) string {
	hint := "按 / 输入地址，例如 chatgpt.com 或 https://example.com/"
	if m.search.focused() {
		hint = "输入域名、IP 或网址，按 enter 查询"
	}
	return inputView(&m.search.input, hint, w) + "\n" + muted.Render(strings.Repeat("─", w)) + "\n"
}

func (m *Model) explainRows() []row {
	e := m.explain
	if e == nil {
		return nil
	}
	if e.err != "" {
		return []row{{text: bad.Render(e.query + "：" + e.err)}, blank()}
	}
	v := e.v
	rows := []row{
		{text: bold.Render(e.query) + muted.Render(" → ") + bold.Render(v.Target) + muted.Render("  "+v.Outbound)},
		{text: "  命中：" + v.Matched},
	}
	if v.Resolved != "" {
		rows = append(rows, row{text: muted.Render("  本机解析为 " + v.Resolved + " 后按 IP 匹配")})
	}
	if len(v.Shadowed) > 0 {
		rows = append(rows, row{text: muted.Render("  也匹配，但被压过了：")})
		for _, s := range v.Shadowed {
			rows = append(rows, row{text: muted.Render("    " + s)})
		}
	}
	if len(v.Uncertain) > 0 {
		rows = append(rows, row{text: muted.Render("  要等到运行时才能确定的规则：")})
		for _, s := range v.Uncertain {
			rows = append(rows, row{text: muted.Render("    " + s)})
		}
	}
	return append(rows, blank())
}

func (m *Model) routeRows(w int) []row {
	rows := m.explainRows()
	t := m.routes
	if t == nil {
		return append(rows, row{text: muted.Render("还没有路由表")})
	}
	col := 24
	for _, es := range [][]view.Entry{t.Apps, t.Domains, t.IPs} {
		for _, e := range es {
			col = max(col, min(40, 2+2*e.Depth+width(e.Target)+2))
		}
	}
	entry := func(e view.Entry, note string) row {
		target := strings.Repeat("  ", e.Depth+1) + e.Target
		via := "→ " + e.Via + note
		var src string
		if e.Expires != nil {
			src = warn.Render("临时，到 " + clock(*e.Expires))
		} else {
			src = muted.Render(shortSource(e.Source))
		}
		return row{text: spread(fit(target, col)+via, src, w), item: entryItem{e}}
	}
	section := func(name string, es []view.Entry, note func(view.Entry) string) {
		if len(es) == 0 {
			return
		}
		rows = append(rows, title(name))
		for _, e := range es {
			rows = append(rows, entry(e, note(e)))
		}
	}
	none := func(view.Entry) string { return "" }
	section("应用条目", t.Apps, none)
	section("手动条目（越具体越优先，与书写顺序无关）", t.Domains, none)
	section("IP 条目（前缀越长越优先）", t.IPs, func(e view.Entry) string {
		if e.Resolve {
			return muted.Render("（也匹配解析后的域名）")
		}
		return ""
	})
	if len(t.Lists) > 0 {
		rows = append(rows, title("规则列表（从上到下）"))
		for i, l := range t.Lists {
			via := "→ " + l.Via
			if l.Subscription {
				via = muted.Render(fmt.Sprintf("订阅自带的规则（%d 条）", l.Rules))
			}
			rows = append(rows, row{text: spread(fit(fmt.Sprintf("  %d. %s", i+1, l.Name), col)+via, muted.Render(shortSource(l.Source)), w)})
		}
	}
	rows = append(rows, title("默认出口"), row{text: fit("", col) + "→ " + t.Default})
	if t.Builtins > 0 {
		rows = append(rows, row{text: muted.Render(fmt.Sprintf("  另有内置的 lan 条目 %d 条：局域网和本机地址走直连。", t.Builtins))})
	}
	return rows
}

func (m *Model) routesKey(key string, item any) tea.Cmd {
	switch key {
	case "/":
		m.search.input.SetValue("")
		return m.search.input.Focus()
	case "esc":
		m.explain = nil
	case "a":
		m.dialog = newRouteDialog(m, "添加条目", "", nil, "")
	case "e", "enter":
		if it, ok := item.(entryItem); ok {
			title := "修改条目的出口"
			if !it.e.Managed {
				title = "覆盖 profile.yaml 里的条目（选择有效期，生成临时条目）"
			}
			d := newRouteDialog(m, title, "", []string{it.e.Target}, it.e.Via)
			if !it.e.Managed {
				d.ttl = 2 // profile.yaml is never rewritten; offer a temporary route
			}
			m.dialog = d
		}
	case "d", "delete", "backspace":
		if it, ok := item.(entryItem); ok {
			if !it.e.Managed {
				m.note(fmt.Sprintf("%s 写在 %s，conch 不会改动你手写的文件；可以按 e 用临时条目覆盖它", it.e.Target, shortSource(it.e.Source)), true)
				return nil
			}
			target := it.e.Target
			m.dialog = &confirmDialog{
				question: fmt.Sprintf("删除条目 %s → %s？", target, it.e.Via),
				yes:      m.do("已删除条目 "+target, func(ctx context.Context) error { return m.c.DeleteRoute(ctx, target) }),
			}
		}
	}
	return nil
}

// shortSource drops the directory from file:line; the files are the
// profile and managed.yaml next to it.
func shortSource(src string) string {
	if i := strings.LastIndexAny(src, `/\`); i >= 0 {
		return src[i+1:]
	}
	return src
}
