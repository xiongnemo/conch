package tui

import (
	"fmt"
	"strings"
	"time"

	"charm.land/bubbles/v2/textinput"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// Basic ANSI colors follow the terminal's own theme, light or dark.
var (
	accent     = lipgloss.NewStyle().Foreground(lipgloss.Color("4"))
	good       = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	bad        = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	warn       = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	muted      = lipgloss.NewStyle().Faint(true)
	bold       = lipgloss.NewStyle().Bold(true)
	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("4"))
	cursorRow  = lipgloss.NewStyle().Reverse(true)
	tabOn      = lipgloss.NewStyle().Bold(true).Reverse(true).Padding(0, 1)
	tabOff     = lipgloss.NewStyle().Padding(0, 1)
	box        = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("4")).Padding(0, 1)
)

// width is how many cells s takes; CJK characters take two.
func width(s string) int { return lipgloss.Width(s) }

// truncate shortens s to at most w cells.
func truncate(s string, w int) string {
	if w <= 0 {
		return ""
	}
	return ansi.Truncate(s, w, "…")
}

// fit makes s exactly w cells wide.
func fit(s string, w int) string {
	s = truncate(s, w)
	return s + strings.Repeat(" ", max(0, w-width(s)))
}

// spread puts left and right on one line of w cells, shortening left first.
func spread(left, right string, w int) string {
	rw := width(right)
	if rw >= w {
		return truncate(right, w)
	}
	left = truncate(left, w-rw-1)
	return left + strings.Repeat(" ", max(1, w-width(left)-rw)) + right
}

func bytesText(n int64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	f, i := float64(n), 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}

// sparkline draws the last w samples, scaled to the largest.
func sparkline(samples []int64, w int) string {
	if len(samples) > w {
		samples = samples[len(samples)-w:]
	}
	top := int64(1024)
	for _, s := range samples {
		top = max(top, s)
	}
	bars := []rune("▁▂▃▄▅▆▇█")
	var b strings.Builder
	for _, s := range samples {
		b.WriteRune(bars[min(len(bars)-1, int(s*int64(len(bars)-1)/top))])
	}
	return b.String()
}

func clock(t time.Time) string { return t.Local().Format("15:04") }

func delayText(ms int64, err string) string {
	switch {
	case err != "":
		return bad.Render("失败")
	case ms < 300:
		return good.Render(fmt.Sprintf("%d ms", ms))
	case ms < 1000:
		return warn.Render(fmt.Sprintf("%d ms", ms))
	default:
		return bad.Render(fmt.Sprintf("%d ms", ms))
	}
}

var kindNames = map[string]string{"select": "手动选择", "url-test": "自动最快", "fallback": "故障转移", "load-balance": "负载均衡"}

var stateNames = map[string]string{"running": "运行中", "starting": "启动中", "crashed": "已崩溃，正在重启", "stopped": "已停止"}

func outboundLabel(name string) string {
	switch name {
	case "DIRECT":
		return "DIRECT（直连）"
	case "REJECT":
		return "REJECT（屏蔽）"
	}
	return name
}

// inputView draws a text input w cells wide, with a hint while it is
// empty. (The input's own placeholder miscounts the width of CJK text.)
func inputView(in *textinput.Model, hint string, w int) string {
	if in.Value() == "" {
		in.SetWidth(0)
		v := in.View()
		return v + muted.Render(truncate(hint, w-width(v)))
	}
	in.SetWidth(max(1, w-width(in.Prompt)-1))
	return in.View()
}
