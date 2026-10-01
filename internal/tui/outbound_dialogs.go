package tui

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"nautilus/internal/daemon"
)

// linkDialog adds a node from a share link.
type linkDialog struct {
	input textinput.Model
}

func newLinkDialog() *linkDialog {
	d := &linkDialog{input: textinput.New()}
	d.input.Prompt = ""
	d.input.Focus()
	return d
}

func (d *linkDialog) key(m *Model, k tea.KeyPressMsg) tea.Cmd {
	switch k.String() {
	case "esc":
		m.dialog = nil
		return nil
	case "enter":
		link := strings.TrimSpace(d.input.Value())
		if link == "" {
			return nil
		}
		m.dialog = nil
		return m.call(func(ctx context.Context) tea.Msg {
			name, err := m.c.AddNode(ctx, link)
			return doneMsg{ok: "已添加节点 " + name, err: err}
		})
	}
	var cmd tea.Cmd
	d.input, cmd = d.input.Update(k)
	return cmd
}

func (d *linkDialog) view(_ *Model, w, h int) string {
	inner := max(30, min(76, w-6))
	return centered(strings.Join([]string{
		bold.Render("添加节点"), "",
		inputView(&d.input, "粘贴分享链接：vmess://、vless://、ss://、trojan://、hysteria2://……", inner),
		"", muted.Render(d.hints()),
	}, "\n"), w, h)
}

func (d *linkDialog) hints() string { return "enter 添加 · esc 取消" }

// chainDialog builds a chain hop by hop from the outbounds there are.
type chainDialog struct {
	editing bool // the name is fixed
	name    textinput.Model
	filter  textinput.Model
	hops    []string
	all     []daemon.Outbound
	pick    int
	focus   int // 0 name, 1 hops
}

func newChainDialog(m *Model, name string, hops []string) *chainDialog {
	d := &chainDialog{editing: name != "", name: textinput.New(), filter: textinput.New(), hops: slices.Clone(hops)}
	d.name.Prompt, d.filter.Prompt = "", "筛选："
	d.name.SetValue(name)
	for _, o := range m.outbounds {
		if o.Kind != "builtin" && o.Name != "GLOBAL" && o.Name != name {
			d.all = append(d.all, o)
		}
	}
	if d.editing {
		d.focus = 1
		d.filter.Focus()
	} else {
		d.name.Focus()
	}
	return d
}

// candidates are what the next hop may be: anything first, nodes after.
func (d *chainDialog) candidates() []daemon.Outbound {
	q := strings.ToLower(strings.TrimSpace(d.filter.Value()))
	var out []daemon.Outbound
	for _, o := range d.all {
		if (len(d.hops) == 0 || o.Kind == "node") && strings.Contains(strings.ToLower(o.Name), q) {
			out = append(out, o)
		}
	}
	return out
}

func (d *chainDialog) setFocus(f int) {
	if d.editing {
		f = 1
	}
	d.focus = f
	d.name.Blur()
	d.filter.Blur()
	if f == 0 {
		d.name.Focus()
	} else {
		d.filter.Focus()
	}
}

func (d *chainDialog) key(m *Model, k tea.KeyPressMsg) tea.Cmd {
	key := k.String()
	switch key {
	case "esc":
		m.dialog = nil
		return nil
	case "tab", "shift+tab":
		d.setFocus(1 - d.focus)
		return nil
	case "ctrl+s":
		return d.save(m)
	}
	var cmd tea.Cmd
	if d.focus == 0 {
		if key == "enter" || key == "down" {
			d.setFocus(1)
			return nil
		}
		d.name, cmd = d.name.Update(k)
		return cmd
	}
	cands := d.candidates()
	switch key {
	case "up":
		d.pick = max(0, d.pick-1)
		return nil
	case "down":
		d.pick = min(len(cands)-1, d.pick+1)
		return nil
	case "enter":
		if len(cands) > 0 {
			d.hops = append(d.hops, cands[min(d.pick, len(cands)-1)].Name)
			d.filter.SetValue("")
			d.pick = 0
		}
		return nil
	case "backspace":
		if d.filter.Value() == "" && len(d.hops) > 0 {
			d.hops = d.hops[:len(d.hops)-1]
			return nil
		}
	}
	d.filter, cmd = d.filter.Update(k)
	d.pick = max(0, min(d.pick, len(d.candidates())-1))
	return cmd
}

func (d *chainDialog) save(m *Model) tea.Cmd {
	name := strings.TrimSpace(d.name.Value())
	if name == "" || len(d.hops) < 2 {
		m.note("链需要名字和至少两跳", true)
		return nil
	}
	hops := slices.Clone(d.hops)
	m.dialog = nil
	return m.do("已保存链 "+name, func(ctx context.Context) error { return m.c.SetChain(ctx, name, hops) })
}

func (d *chainDialog) view(_ *Model, w, h int) string {
	inner := max(30, min(72, w-6))
	label := func(text string, focus int) string {
		if d.focus == focus {
			return accent.Render(fit("▸ "+text, 10))
		}
		return muted.Render(fit("  "+text, 10))
	}
	title := "新建链"
	if d.editing {
		title = "修改链 " + d.name.Value()
	}
	lines := []string{bold.Render(title), ""}
	if !d.editing {
		lines = append(lines, label("名字", 0)+inputView(&d.name, "例如 AI-Exit", inner-12))
	}
	path := muted.Render("（还没有）")
	if len(d.hops) > 0 {
		path = strings.Join(d.hops, muted.Render(" → "))
	}
	next := "第一跳（可以是出口组）"
	if len(d.hops) > 0 {
		next = fmt.Sprintf("第 %d 跳（节点）", len(d.hops)+1)
	}
	lines = append(lines, label("各跳", 1)+path, fit("", 10)+muted.Render("选择"+next+"：")+inputView(&d.filter, "", inner-30))
	cands := d.candidates()
	const shown = 8
	start := max(0, min(d.pick-shown/2, len(cands)-shown))
	for i := start; i < len(cands) && i < start+shown; i++ {
		o := cands[i]
		desc := map[string]string{"group": "出口组", "chain": "链", "node": "节点"}[o.Kind]
		text := "  " + spread(o.Name, muted.Render(desc), inner-16)
		if i == d.pick && d.focus == 1 {
			text = cursorRow.Render(fit(ansi.Strip(text), inner-14))
		}
		lines = append(lines, fit("", 12)+text)
	}
	if len(cands) == 0 {
		lines = append(lines, fit("", 12)+muted.Render("没有可选的出口"))
	}
	lines = append(lines, "", muted.Render(d.hints()))
	return centered(strings.Join(lines, "\n"), w, h)
}

func (d *chainDialog) hints() string {
	if d.focus == 0 {
		return "enter 下一步 · esc 取消"
	}
	return "↑↓ 选择 · enter 加一跳 · backspace 去掉最后一跳 · ctrl+s 保存 · esc 取消"
}
