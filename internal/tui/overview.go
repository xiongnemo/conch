package tui

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
)

type subItem struct{ name string }

func (m *Model) overviewRows(w int) []row {
	s := m.status
	if s == nil {
		if m.connErr != "" {
			return []row{{text: bad.Render(m.connErr)}, {text: muted.Render("正在重试……")}}
		}
		return []row{{text: muted.Render("正在连接 daemon……")}}
	}
	field := func(name, value string) row { return row{text: fit(muted.Render(name), 10) + value} }
	kernel := s.Backend + " · " + s.Kernel.State.Text()
	if s.Kernel.Restarts > 0 {
		kernel += fmt.Sprintf("（重启过 %d 次）", s.Kernel.Restarts)
	}
	var modes []string
	for _, mode := range []string{"rule", "global", "direct"} {
		if mode == s.Mode {
			modes = append(modes, accent.Render("● "+modeName(mode)))
		} else {
			modes = append(modes, muted.Render("○ "+modeName(mode)))
		}
	}
	sysproxy := muted.Render("关")
	if s.SysProxy {
		sysproxy = good.Render("开") + muted.Render("（daemon 退出时恢复原来的设置）")
	}
	tun := muted.Render("关")
	if s.TUN {
		tun = good.Render("开") + muted.Render("（所有程序的流量都经过 nautilus）")
	}
	port := "-"
	if s.MixedPort != 0 {
		port = fmt.Sprintf("127.0.0.1:%d（HTTP 和 SOCKS5）", s.MixedPort)
	}
	rows := []row{
		field("内核", kernel),
		field("模式", strings.Join(modes, "  ")),
		field("系统代理", sysproxy),
		field("TUN", tun),
		field("代理端口", port),
		field("配置文件", s.Profile),
		blank(),
	}

	var up, down int64
	if n := len(m.up); n > 0 {
		up, down = m.up[n-1], m.down[n-1]
	}
	rows = append(rows, field("实时流量", fmt.Sprintf("↑ %s/s   ↓ %s/s", bytesText(up), bytesText(down))))
	if len(m.down) > 1 {
		rows = append(rows,
			row{text: fit("", 10) + accent.Render(sparkline(m.down, w-12)) + muted.Render(" ↓")},
			row{text: fit("", 10) + good.Render(sparkline(m.up, w-12)) + muted.Render(" ↑")})
	}
	rows = append(rows, blank(), title("订阅"))
	names := slices.Sorted(maps.Keys(s.Subscriptions))
	if len(names) == 0 {
		rows = append(rows, row{text: muted.Render("  没有订阅")})
	}
	for _, name := range names {
		info := s.Subscriptions[name]
		parts := []string{}
		if info.Summary != "" {
			parts = append(parts, info.Summary)
		}
		if info.Total > 0 {
			parts = append(parts, fmt.Sprintf("已用 %s / %s", bytesText(info.Upload+info.Download), bytesText(info.Total)))
		}
		if info.Expire > 0 {
			parts = append(parts, "到期 "+time.Unix(info.Expire, 0).Local().Format("2006-01-02"))
		}
		if !info.FetchedAt.IsZero() {
			parts = append(parts, "更新于 "+info.FetchedAt.Local().Format("01-02 15:04"))
		}
		rows = append(rows, row{text: "  " + fit(name, 20) + muted.Render(strings.Join(parts, " · ")), item: subItem{name}})
	}

	if s.Error != "" {
		rows = append(rows, blank(), row{text: bad.Render("配置有问题，内核继续使用上一份可用的配置：")})
		for _, l := range strings.Split(s.Error, "\n") {
			rows = append(rows, row{text: "  " + l})
		}
	}
	if len(s.Diagnostics) > 0 {
		rows = append(rows, blank(), title("提示"))
		for _, d := range s.Diagnostics {
			rows = append(rows, row{text: "  " + warn.Render(d)})
		}
	}
	return rows
}

func (m *Model) overviewKey(key string, item any) tea.Cmd {
	s := m.status
	if s == nil {
		return nil
	}
	switch key {
	case "m":
		next := map[string]string{"rule": "global", "global": "direct", "direct": "rule"}[s.Mode]
		if next == "" {
			next = "rule"
		}
		return m.do("已切换到"+modeName(next)+"模式", func(ctx context.Context) error { return m.c.SetMode(ctx, next) })
	case "s":
		on := !s.SysProxy
		ok := "系统代理已关闭，已恢复原来的设置"
		if on {
			ok = "系统代理已开启"
		}
		return m.do(ok, func(ctx context.Context) error { return m.c.SetSysProxy(ctx, on) })
	case "t":
		on := !s.TUN
		ok := "TUN 已关闭"
		if on {
			ok = "TUN 已开启"
			m.note("正在开启 TUN……", false)
		}
		return m.do(ok, func(ctx context.Context) error { return m.c.SetTUN(ctx, on) })
	case "u":
		if sub, ok := item.(subItem); ok {
			m.note("正在更新订阅 "+sub.name+"……", false)
			return m.do("订阅 "+sub.name+" 已更新", func(ctx context.Context) error { return m.c.UpdateSubscription(ctx, sub.name) })
		}
	case "R":
		m.dialog = &confirmDialog{question: "重启内核？正在进行的连接会断开。", yes: m.do("内核已重启", m.c.Restart)}
	}
	return nil
}
