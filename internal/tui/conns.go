package tui

import (
	"context"
	"fmt"
	"net"
	"strings"

	tea "charm.land/bubbletea/v2"

	"nautilus/internal/daemon"
)

type (
	failedItem struct{ f daemon.Failed }
	connItem   struct{ c daemon.Connection }
)

func (m *Model) connRows(w int) []row {
	var rows []row
	rows = append(rows, title("加载失败的网站"))
	if len(m.failed) == 0 {
		rows = append(rows, row{text: muted.Render("  还没有失败的连接")})
	}
	for _, f := range m.failed {
		left := "  " + fit(net.JoinHostPort(f.Host, f.Port), 30) + bad.Render(fmt.Sprintf("%d 次", f.Count)) + muted.Render(" · 经由 "+f.Via+" · "+f.Error)
		rows = append(rows, row{text: truncate(left, w), item: failedItem{f}})
	}

	live := m.status == nil || m.status.Caps.LiveConnections
	rows = append(rows, blank())
	if live {
		rows = append(rows, title("当前连接"))
	} else {
		rows = append(rows, title("最近的连接"), row{text: muted.Render("  这个内核不提供连接列表，这里列出最近十分钟内新建的连接")})
	}
	switch {
	case m.connsErr != "":
		rows = append(rows, row{text: bad.Render("  " + m.connsErr)})
	case len(m.conns) == 0:
		rows = append(rows, row{text: muted.Render("  没有连接")})
	}
	for _, c := range m.conns {
		target := net.JoinHostPort(c.Host, c.Port)
		if c.Process != "" {
			target += muted.Render(" " + c.Process)
		}
		left := "  " + fit(target, 30) + c.Matched + muted.Render(" · "+strings.Join(c.Via, " → "))
		right := muted.Render(clock(c.Start))
		if live {
			right = muted.Render(fmt.Sprintf("↑%s ↓%s", bytesText(c.Upload), bytesText(c.Download)))
		}
		rows = append(rows, row{text: spread(left, right, w), item: connItem{c}})
	}
	return rows
}

func (m *Model) connsKey(key string, item any) tea.Cmd {
	var host string
	switch it := item.(type) {
	case failedItem:
		host = it.f.Host
	case connItem:
		host = it.c.Host
	}
	switch key {
	case "r", "enter":
		if host == "" {
			return nil
		}
		return m.call(func(ctx context.Context) tea.Msg {
			targets, err := m.c.Suggest(ctx, host)
			return suggestMsg{host: host, targets: targets, err: err}
		})
	case "x":
		it, ok := item.(connItem)
		if !ok {
			return nil
		}
		if m.status != nil && !m.status.Caps.CloseConnection {
			m.note(m.status.Backend+" 内核不能断开单个连接", true)
			return nil
		}
		id := it.c.ID
		return m.do("已断开 "+host, func(ctx context.Context) error { return m.c.CloseConnection(ctx, id) })
	case "c":
		return m.do("已清空失败记录", m.c.ClearFailed)
	}
	return nil
}
