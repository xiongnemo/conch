package tui

import (
	"regexp"
	"strings"
	"time"
)

type logItem struct{ i int }

// logRows shows the kernel's log, every line selectable so the cursor
// can scroll through it.
func (m *Model) logRows() []row {
	if len(m.logs) == 0 {
		return []row{{text: muted.Render("还没有日志")}}
	}
	rows := make([]row, len(m.logs))
	for i, l := range m.logs {
		rows[i] = row{text: prettyLog(l), item: logItem{i}}
	}
	return rows
}

var (
	// mihomo: time="2026-10-01T23:31:07.03+10:00" level=info msg="…"
	mihomoLog = regexp.MustCompile(`^time="([^"]+)" level=(\w+) msg="(.*)"$`)
	// xray: 2026/10/01 23:31:07.123456 [Warning] …
	xrayLog = regexp.MustCompile(`^\d{4}/\d\d/\d\d (\d\d:\d\d:\d\d)(?:\.\d+)? (?:\[(\w+)\] )?(.*)$`)
)

// prettyLog shortens a kernel log line to time, level and message.
func prettyLog(line string) string {
	var at, level, msg string
	if m := mihomoLog.FindStringSubmatch(line); m != nil {
		if t, err := time.Parse(time.RFC3339Nano, m[1]); err == nil {
			at = t.Local().Format("15:04:05")
		}
		level, msg = m[2], strings.ReplaceAll(m[3], `\"`, `"`)
	} else if m := xrayLog.FindStringSubmatch(line); m != nil {
		at, level, msg = m[1], strings.ToLower(m[2]), m[3]
	} else {
		return line
	}
	switch level {
	case "warning":
		msg = warn.Render(msg)
	case "error", "fatal":
		msg = bad.Render(msg)
	}
	return muted.Render(at) + " " + msg
}
