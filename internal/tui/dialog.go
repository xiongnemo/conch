package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/xiongnemo/conch/internal/daemon"
)

// dialog takes over the keyboard until it closes itself.
type dialog interface {
	key(m *Model, k tea.KeyPressMsg) tea.Cmd
	view(m *Model, w, h int) string
	hints() string
}

func centered(content string, w, h int) string {
	return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, box.Render(content))
}

type confirmDialog struct {
	question string
	yes      tea.Cmd
}

func (d *confirmDialog) key(m *Model, k tea.KeyPressMsg) tea.Cmd {
	switch k.String() {
	case "y", "enter":
		m.dialog = nil
		return d.yes
	case "n", "esc", "q":
		m.dialog = nil
	}
	return nil
}

func (d *confirmDialog) view(_ *Model, w, h int) string {
	return centered(d.question+"\n\n"+muted.Render("y 确定 · n 取消"), w, h)
}

func (d *confirmDialog) hints() string { return "y 确定 · n 取消" }

var ttls = []struct {
	label string
	d     time.Duration
}{{"永久", 0}, {"30 分钟", 30 * time.Minute}, {"1 小时", time.Hour}, {"8 小时", 8 * time.Hour}}

// routeDialog sends a target to an outbound: the "指哪打哪" form behind
// adding entries, editing them and routing a site from a connection.
type routeDialog struct {
	title   string
	host    string   // the site the dialog is for, if any
	targets []string // choices for the target; none means typing it
	target  int
	input   textinput.Model
	filter  textinput.Model
	vias    []daemon.Outbound
	via     int // in the filtered list
	ttl     int
	focus   int // 0 target, 1 outbound, 2 duration
}

func newRouteDialog(m *Model, title, host string, targets []string, via string) *routeDialog {
	d := &routeDialog{title: title, host: host, targets: targets, input: textinput.New(), filter: textinput.New()}
	d.input.Prompt = ""
	d.filter.Prompt = "筛选："
	// Groups and chains are what entries usually point at; nodes are many.
	order := map[string]int{"group": 0, "chain": 1, "builtin": 2, "node": 3}
	for k := range 4 {
		for _, o := range m.outbounds {
			// GLOBAL is what global mode uses, not a place to route to.
			if order[o.Kind] == k && o.Name != "GLOBAL" {
				d.vias = append(d.vias, o)
			}
		}
	}
	for i, o := range d.vias {
		if o.Name == via {
			d.via = i
		}
	}
	if len(targets) == 0 {
		d.input.Focus()
	} else {
		d.focus = 1
		d.filter.Focus()
	}
	return d
}

func (d *routeDialog) filtered() []daemon.Outbound {
	q := strings.ToLower(strings.TrimSpace(d.filter.Value()))
	if q == "" {
		return d.vias
	}
	var out []daemon.Outbound
	for _, o := range d.vias {
		if strings.Contains(strings.ToLower(o.Name), q) {
			out = append(out, o)
		}
	}
	return out
}

func (d *routeDialog) setFocus(f int) {
	d.focus = (f + 3) % 3
	d.input.Blur()
	d.filter.Blur()
	switch d.focus {
	case 0:
		if len(d.targets) == 0 {
			d.input.Focus()
		}
	case 1:
		d.filter.Focus()
	}
}

func (d *routeDialog) key(m *Model, k tea.KeyPressMsg) tea.Cmd {
	key := k.String()
	switch key {
	case "esc":
		m.dialog = nil
		return nil
	case "tab":
		d.setFocus(d.focus + 1)
		return nil
	case "shift+tab":
		d.setFocus(d.focus - 1)
		return nil
	case "enter":
		return d.submit(m)
	}
	switch d.focus {
	case 0:
		if len(d.targets) > 0 {
			switch key {
			case "left", "h":
				d.target = (d.target + len(d.targets) - 1) % len(d.targets)
			case "right", "l", "space":
				d.target = (d.target + 1) % len(d.targets)
			case "down", "j":
				d.setFocus(1)
			}
			return nil
		}
		if key == "down" {
			d.setFocus(1)
			return nil
		}
		var cmd tea.Cmd
		d.input, cmd = d.input.Update(k)
		return cmd
	case 1:
		n := len(d.filtered())
		switch key {
		case "up":
			if d.via == 0 {
				d.setFocus(0)
			} else {
				d.via--
			}
			return nil
		case "down":
			if d.via >= n-1 {
				d.setFocus(2)
			} else {
				d.via++
			}
			return nil
		case "pgup":
			d.via = max(0, d.via-8)
			return nil
		case "pgdown":
			d.via = max(0, min(n-1, d.via+8))
			return nil
		}
		var cmd tea.Cmd
		d.filter, cmd = d.filter.Update(k)
		d.via = max(0, min(len(d.filtered())-1, d.via))
		return cmd
	case 2:
		switch key {
		case "left", "h":
			d.ttl = (d.ttl + len(ttls) - 1) % len(ttls)
		case "right", "l", "space":
			d.ttl = (d.ttl + 1) % len(ttls)
		case "up", "k":
			d.setFocus(1)
		}
	}
	return nil
}

func (d *routeDialog) submit(m *Model) tea.Cmd {
	target := strings.TrimSpace(d.input.Value())
	if len(d.targets) > 0 {
		target = d.targets[d.target]
	}
	vias := d.filtered()
	if target == "" || len(vias) == 0 {
		m.note("请填写目标并选择出口", true)
		return nil
	}
	via, ttl := vias[min(d.via, len(vias)-1)].Name, ttls[d.ttl]
	m.dialog = nil
	ok := fmt.Sprintf("已添加条目 %s → %s", target, via)
	if ttl.d > 0 {
		ok += "（" + ttl.label + "后自动删除）"
	}
	return m.do(ok, func(ctx context.Context) error { return m.c.SetRoute(ctx, target, via, ttl.d) })
}

func (d *routeDialog) view(m *Model, w, h int) string {
	inner := max(30, min(72, w-6))
	label := func(text string, focus int) string {
		if d.focus == focus {
			return accent.Render(fit("▸ "+text, 10))
		}
		return muted.Render(fit("  "+text, 10))
	}
	lines := []string{bold.Render(d.title), ""}
	if d.host != "" {
		lines = append(lines, label("网站", -1)+d.host)
	}
	if len(d.targets) > 0 {
		t := d.targets[d.target]
		if d.target == 0 && len(d.targets) > 1 {
			t += muted.Render("（包含所有子域名）")
		}
		if len(d.targets) > 1 {
			t = "‹ " + t + " ›"
		}
		lines = append(lines, label("目标", 0)+t)
	} else {
		lines = append(lines, label("目标", 0)+inputView(&d.input, "域名、=精确域名、IP/网段 或 app:应用名", inner-12))
	}
	lines = append(lines, label("出口", 1)+inputView(&d.filter, "输入名字的一部分", inner-12))
	vias := d.filtered()
	const shown = 8
	start := max(0, min(d.via-shown/2, len(vias)-shown))
	for i := start; i < len(vias) && i < start+shown; i++ {
		o := vias[i]
		desc := map[string]string{"group": "出口组", "chain": "链", "node": "节点", "builtin": ""}[o.Kind]
		if o.Kind == "group" && current(&o) != "" {
			desc += " · 当前 " + current(&o)
		}
		text := "  " + spread(outboundLabel(o.Name), muted.Render(desc), inner-16)
		if i == d.via {
			if d.focus == 1 {
				text = cursorRow.Render(fit(ansi.Strip(text), inner-14))
			} else {
				text = accent.Render("●") + text[1:]
			}
		}
		lines = append(lines, fit("", 12)+text)
	}
	if len(vias) == 0 {
		lines = append(lines, fit("", 12)+muted.Render("没有匹配的出口"))
	}
	lines = append(lines, label("有效期", 2)+"‹ "+ttls[d.ttl].label+" ›", "", muted.Render(d.hints()))
	return centered(strings.Join(lines, "\n"), w, h)
}

func (d *routeDialog) hints() string {
	switch d.focus {
	case 0:
		if len(d.targets) > 1 {
			return "←→ 选择目标 · tab 下一项 · enter 确定 · esc 取消"
		}
		return "tab 下一项 · enter 确定 · esc 取消"
	case 1:
		return "↑↓ 选择出口 · 输入文字筛选 · tab 下一项 · enter 确定 · esc 取消"
	}
	return "←→ 选择有效期 · enter 确定 · esc 取消"
}
