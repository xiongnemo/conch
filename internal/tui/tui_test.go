package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/xiongnemo/conch/internal/api"
	"github.com/xiongnemo/conch/internal/control"
	"github.com/xiongnemo/conch/internal/daemon"
	"github.com/xiongnemo/conch/internal/kernel"
	"github.com/xiongnemo/conch/internal/subscription"
	"github.com/xiongnemo/conch/internal/view"
)

// fake is a daemon that records what the TUI asks of it.
type fake struct {
	mu     sync.Mutex
	calls  []string
	events chan api.Event
	status daemon.Status
	live   bool
}

func newFake() *fake {
	return &fake{events: make(chan api.Event, 16), live: true, status: daemon.Status{
		Ready: true, Backend: "mihomo", Kernel: kernel.Status{State: kernel.Running}, Mode: "rule", MixedPort: 7890,
		Profile: "/home/u/profile.yaml", Caps: control.Caps{LiveConnections: true, CloseConnection: true},
		Subscriptions: map[string]*subscription.Info{"airport": {Total: 100 << 30, Download: 12 << 30, FetchedAt: time.Date(2026, 10, 1, 12, 0, 0, 0, time.Local)}},
	}}
}

func (f *fake) record(format string, args ...any) {
	f.mu.Lock()
	f.calls = append(f.calls, fmt.Sprintf(format, args...))
	f.mu.Unlock()
}

func (f *fake) called(call string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c == call {
			return true
		}
	}
	return false
}

func (f *fake) Status(context.Context) (daemon.Status, error) { return f.status, nil }

func (f *fake) Outbounds(context.Context) ([]daemon.Outbound, error) {
	return []daemon.Outbound{
		{Name: "DIRECT", Kind: "builtin", UDP: true}, {Name: "REJECT", Kind: "builtin"},
		{Name: "节点选择", Kind: "group", Type: "select", Members: []string{"HK 01", "JP 01"}, Selected: "HK 01", Now: "HK 01"},
		{Name: "香港自动", Kind: "group", Type: "url-test", Members: []string{"HK 01", "HK 02"}, Now: "HK 02"},
		{Name: "AI-Exit", Kind: "chain", Hops: []string{"香港自动", "home"}, UDP: true, Managed: true, Source: "/home/u/managed.yaml:3"},
		{Name: "HK 01", Kind: "node", Type: "vmess", Server: "1.2.3.4:443", UDP: true, Source: "/home/u/profile.yaml:3"},
		{Name: "HK 02", Kind: "node", Type: "trojan", Server: "1.2.3.5:443"},
		{Name: "JP 01", Kind: "node", Type: "ss", Server: "1.2.3.6:8388"},
		{Name: "home", Kind: "node", Type: "socks5", Server: "5.6.7.8:1080", Managed: true},
	}, nil
}

func (f *fake) Routes(context.Context) (view.Table, error) {
	exp := time.Date(2026, 10, 1, 15, 4, 0, 0, time.Local)
	return view.Table{
		Domains: []view.Entry{
			{Target: "google.com", Via: "节点选择", Source: "/home/u/profile.yaml:8"},
			{Target: "mail.google.com", Via: "DIRECT", Source: "profile.yaml:9", Depth: 1},
			{Target: "openai.com", Via: "AI-Exit", Source: "managed.yaml:1", Managed: true},
			{Target: "x.com", Via: "JP 01", Expires: &exp, Managed: true},
		},
		IPs:     []view.Entry{{Target: "10.0.0.0/8", Via: "DIRECT", Source: "profile.yaml:12"}},
		Lists:   []view.List{{Name: "geosite:cn", Via: "DIRECT", Rules: 1}, {Name: "airport", Subscription: true, Rules: 120}},
		Default: "节点选择", Builtins: 14,
	}, nil
}

func (f *fake) Explain(_ context.Context, target, _ string) (view.Explanation, error) {
	f.record("explain %s", target)
	return view.Explanation{Target: "AI-Exit", Outbound: "链 AI-Exit：香港自动（自动最快） → home", Matched: "手动条目 openai.com（managed.yaml:1）",
		Shadowed: []string{"规则列表 airport → 节点选择"}}, nil
}

func (f *fake) SetRoute(_ context.Context, target, via string, ttl time.Duration) error {
	f.record("route %s %s %s", target, via, ttl)
	return nil
}

func (f *fake) DeleteRoute(_ context.Context, target string) error {
	f.record("delete %s", target)
	return nil
}

func (f *fake) Select(_ context.Context, group, member string) error {
	f.record("select %s %s", group, member)
	return nil
}

func (f *fake) SetChain(_ context.Context, name string, hops []string) error {
	f.record("chain %s %s", name, strings.Join(hops, ">"))
	return nil
}

func (f *fake) DeleteChain(_ context.Context, name string) error {
	f.record("delete chain %s", name)
	return nil
}

func (f *fake) AddNode(_ context.Context, link string) (string, error) {
	f.record("add node %s", link)
	return "JP 02", nil
}

func (f *fake) DeleteNode(_ context.Context, name string) error {
	f.record("delete node %s", name)
	return nil
}

func (f *fake) Delay(_ context.Context, name string) (api.Delay, error) {
	f.record("delay %s", name)
	if name == "AI-Exit" {
		return api.Delay{Delay: 340, Hops: []daemon.HopDelay{{Name: "香港自动", Delay: 120}, {Name: "home", Delay: 340}}}, nil
	}
	if name == "HK 02" {
		return api.Delay{}, &api.APIError{Status: 400, Body: api.Error{Error: "经由 HK 02 测速超时"}}
	}
	return api.Delay{Delay: 88}, nil
}

func (f *fake) SetMode(_ context.Context, mode string) error {
	f.record("mode %s", mode)
	return nil
}

func (f *fake) SetSysProxy(_ context.Context, on bool) error {
	f.record("sysproxy %v", on)
	return nil
}

func (f *fake) SetTUN(_ context.Context, on bool) error {
	f.record("tun %v", on)
	return nil
}

func (f *fake) UpdateSubscription(_ context.Context, name string) error {
	f.record("update %s", name)
	return nil
}

func (f *fake) Restart(context.Context) error {
	f.record("restart")
	return nil
}

func (f *fake) Connections(context.Context) ([]daemon.Connection, error) {
	return []daemon.Connection{{
		Connection: control.Connection{ID: "c1", Host: "chat.openai.com", Port: "443", Process: "curl", Upload: 1200, Download: 34000, Start: time.Now()},
		Matched:    "手动条目 openai.com（managed.yaml:1）", Via: []string{"AI-Exit"},
	}}, nil
}

func (f *fake) CloseConnection(_ context.Context, id string) error {
	f.record("close %s", id)
	return nil
}

func (f *fake) Failed(context.Context) ([]daemon.Failed, error) {
	return []daemon.Failed{{Host: "api.blocked.example", Port: "443", Via: "DIRECT", Count: 3, Error: "connect: connection refused"}}, nil
}

func (f *fake) ClearFailed(context.Context) error {
	f.record("clear")
	return nil
}

func (f *fake) Suggest(_ context.Context, host string) ([]string, error) {
	if host == "api.blocked.example" {
		return []string{"blocked.example", "api.blocked.example"}, nil
	}
	return []string{host}, nil
}

func (f *fake) Logs(context.Context) ([]string, error) { return []string{"kernel started"}, nil }

func (f *fake) Events(context.Context) (<-chan api.Event, error) {
	if !f.live {
		return nil, api.ErrNotRunning
	}
	data, _ := json.Marshal(f.status)
	f.events <- api.Event{Type: "state", Data: data}
	return f.events, nil
}

// harness runs the model's commands synchronously, dropping those that
// wait (ticks, the event stream) so tests stay deterministic.
type harness struct {
	t *testing.T
	m *Model
	f *fake
}

func start(t *testing.T) *harness {
	h := &harness{t: t, f: newFake()}
	h.m = New(context.Background(), h.f)
	h.send(tea.WindowSizeMsg{Width: 110, Height: 32})
	h.run(h.m.Init())
	return h
}

func (h *harness) send(msgs ...tea.Msg) {
	for len(msgs) > 0 {
		msg := msgs[0]
		msgs = msgs[1:]
		_, cmd := h.m.Update(msg)
		msgs = append(msgs, results(cmd)...)
	}
}

func (h *harness) run(cmd tea.Cmd) { h.send(results(cmd)...) }

func results(cmd tea.Cmd) []tea.Msg {
	if cmd == nil {
		return nil
	}
	ch := make(chan tea.Msg, 1)
	go func() { ch <- cmd() }()
	select {
	case msg := <-ch:
		switch msg := msg.(type) {
		case nil:
			return nil
		case tea.BatchMsg:
			var out []tea.Msg
			for _, c := range msg {
				out = append(out, results(c)...)
			}
			return out
		}
		return []tea.Msg{msg}
	case <-time.After(50 * time.Millisecond):
		return nil
	}
}

// keys presses keys: names like "enter" and "tab", or text to type.
func (h *harness) keys(keys ...string) {
	special := map[string]rune{"enter": tea.KeyEnter, "tab": tea.KeyTab, "esc": tea.KeyEscape, "down": tea.KeyDown, "up": tea.KeyUp,
		"left": tea.KeyLeft, "right": tea.KeyRight, "space": tea.KeySpace, "backspace": tea.KeyBackspace}
	for _, k := range keys {
		if code, ok := special[k]; ok {
			h.send(tea.KeyPressMsg{Code: code})
			continue
		}
		if k == "ctrl+s" {
			h.send(tea.KeyPressMsg{Code: 's', Mod: tea.ModCtrl})
			continue
		}
		for _, r := range k {
			h.send(tea.KeyPressMsg{Code: r, Text: string(r)})
		}
	}
}

func (h *harness) screen() string { return ansi.Strip(h.m.View().Content) }

func (h *harness) see(want ...string) {
	h.t.Helper()
	s := h.screen()
	for _, w := range want {
		if !strings.Contains(s, w) {
			h.t.Errorf("screen lacks %q:\n%s", w, s)
			return
		}
	}
}

func (h *harness) cursorOn(text string) {
	h.t.Helper()
	for _, l := range strings.Split(h.m.View().Content, "\n") {
		if strings.Contains(l, "\x1b[7m") && strings.Contains(ansi.Strip(l), text) {
			return
		}
	}
	h.t.Errorf("cursor is not on %q:\n%s", text, h.screen())
}

func (h *harness) wantCall(call string) {
	h.t.Helper()
	if !h.f.called(call) {
		h.t.Errorf("daemon was not asked to %q; calls: %q", call, h.f.calls)
	}
}

func TestOverview(t *testing.T) {
	h := start(t)
	h.see("1 概览", "mihomo 运行中", "● 分流", "127.0.0.1:7890", "airport", "已用 12.0 GB / 100.0 GB")
	h.keys("m")
	h.wantCall("mode global")
	h.keys("s")
	h.wantCall("sysproxy true")
	h.keys("t")
	h.wantCall("tun true")
	h.keys("u") // the subscription is the only item, so the cursor is on it
	h.wantCall("update airport")
	h.keys("R")
	h.see("重启内核？")
	h.keys("y")
	h.wantCall("restart")

	data, _ := json.Marshal(control.Traffic{Up: 2048, Down: 3 << 20})
	h.send(eventMsg{Type: "traffic", Data: data})
	h.see("↑ 2.0 KB/s", "↓ 3.0 MB/s")
}

func TestOutbounds(t *testing.T) {
	h := start(t)
	h.keys("2")
	h.see("节点选择", "手动选择 · 当前 HK 01", "香港自动[HK 02] → home", "UDP", "vmess · 1.2.3.4:443")
	h.cursorOn("节点选择")
	h.keys("enter", "down", "down") // expand, then onto JP 01
	h.cursorOn("JP 01")
	h.keys("enter")
	h.wantCall("select 节点选择 JP 01")

	h.keys("down", "t") // 香港自动: test every member
	h.wantCall("delay HK 01")
	h.wantCall("delay HK 02")
	h.keys("down", "t") // the chain, hop by hop
	h.see("香港自动[HK 02] 120 ms → home 340 ms")
	h.keys("down", "down", "t")
	h.see("失败") // HK 02 timed out

	// Groups that pick members themselves cannot be chosen from.
	h.keys("up", "up", "up", "enter", "down", "enter")
	h.see("自动最快出口组，由内核自动挑选成员")
}

func TestManagedOutbounds(t *testing.T) {
	h := start(t)
	h.keys("2", "n", "vless://x@example.com:443#JP 02", "enter")
	h.wantCall("add node vless://x@example.com:443#JP 02")
	h.see("已添加节点 JP 02")

	// A new chain: a group first, then nodes; backspace takes a hop back.
	h.keys("c", "Exit2", "enter", "香港", "enter", "HK 02", "enter", "backspace", "home", "enter")
	h.see("香港自动 → home")
	h.keys("ctrl+s")
	h.wantCall("chain Exit2 香港自动>home")

	// Only what conch added can be changed or deleted.
	h.keys("down", "down") // the chain AI-Exit
	h.cursorOn("AI-Exit")
	h.keys("e")
	h.see("修改链 AI-Exit", "香港自动 → home")
	h.keys("backspace", "JP", "enter", "ctrl+s")
	h.wantCall("chain AI-Exit 香港自动>JP 01")
	h.keys("down") // HK 01, from profile.yaml
	h.keys("d")
	h.see("写在 profile.yaml:3")
	h.keys("down", "down", "down", "d", "y") // home
	h.wantCall("delete node home")
}

func TestRoutes(t *testing.T) {
	h := start(t)
	h.keys("3")
	h.see("手动条目（越具体越优先", "google.com", "    mail.google.com", "临时，到 15:04", "1. geosite:cn", "订阅自带的规则（120 条）", "→ 节点选择", "内置的 lan 条目 14 条")
	if strings.Contains(h.screen(), "/home/") {
		t.Error("sources should be shown without their directory")
	}

	h.keys("/", "chatgpt.com", "enter")
	h.wantCall("explain chatgpt.com")
	h.see("chatgpt.com → AI-Exit", "命中：手动条目 openai.com", "也匹配，但被压过了", "规则列表 airport → 节点选择")

	// Entries in profile.yaml are never rewritten.
	h.keys("d")
	h.see("conch 不会改动你手写的文件")
	h.keys("down", "down", "d", "y") // openai.com, from managed.yaml
	h.wantCall("delete openai.com")

	h.keys("a", "example.org", "tab", "AI", "tab", "right", "enter")
	h.wantCall("route example.org AI-Exit 30m0s")

	// Overriding a profile.yaml entry makes a temporary route.
	h.keys("up", "up", "e")
	h.see("覆盖 profile.yaml 里的条目", "‹ 1 小时 ›")
	h.keys("enter")
	h.wantCall("route google.com 节点选择 1h0m0s")
}

func TestConnections(t *testing.T) {
	h := start(t)
	h.keys("4")
	h.see("加载失败的网站", "api.blocked.example:443", "3 次 · 经由 DIRECT", "当前连接", "chat.openai.com:443", "curl", "↑1.2 KB ↓33.2 KB")
	h.keys("r")
	h.see("让这个网站走", "‹ blocked.example（包含所有子域名） ›")
	h.keys("香港", "enter")
	h.wantCall("route blocked.example 香港自动 0s")

	h.keys("down", "x")
	h.wantCall("close c1")
	h.keys("c")
	h.wantCall("clear")
}

func TestRecentConnections(t *testing.T) {
	h := start(t)
	h.f.status.Caps = control.Caps{}
	h.f.status.Backend = "xray"
	h.run(h.m.loadStatus())
	h.keys("4")
	h.see("最近的连接", "这个内核不提供连接列表")
	h.keys("down", "x")
	h.see("xray 内核不能断开单个连接")
}

func TestLogs(t *testing.T) {
	h := start(t)
	h.keys("5")
	h.see("kernel started")
	for _, line := range []string{
		`time="2026-10-01T23:31:07.03+10:00" level=info msg="[TCP] 127.0.0.1:1 --> example.com:443 match Match using DIRECT"`,
		`2026/10/01 23:31:08.123456 [Warning] core: Xray 26.3.27 started`,
	} {
		data, _ := json.Marshal(line)
		h.send(eventMsg{Type: "log", Data: data})
	}
	h.see(time.Date(2026, 10, 1, 23, 31, 7, 0, time.FixedZone("", 10*3600)).Local().Format("15:04:05")+" [TCP] 127.0.0.1:1 --> example.com:443 match Match using DIRECT",
		"23:31:08 core: Xray 26.3.27 started")
}

func TestNotRunning(t *testing.T) {
	f := newFake()
	f.live = false
	h := &harness{t: t, f: f, m: New(context.Background(), f)}
	h.send(tea.WindowSizeMsg{Width: 100, Height: 20})
	h.run(h.m.Init())
	h.see("未连接", "conch daemon 没有在运行")
}
