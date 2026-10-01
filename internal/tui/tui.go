// Package tui is the terminal UI. Like the Web UI it is a client of the
// daemon's API: it shows what the daemon reports and asks it for changes.
package tui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"nautilus/internal/api"
	"nautilus/internal/control"
	"nautilus/internal/daemon"
	"nautilus/internal/view"
)

// Client is the part of the daemon's API the TUI uses; *api.Client has it.
type Client interface {
	Status(ctx context.Context) (daemon.Status, error)
	Outbounds(ctx context.Context) ([]daemon.Outbound, error)
	Routes(ctx context.Context) (view.Table, error)
	Explain(ctx context.Context, target, app string) (view.Explanation, error)
	SetRoute(ctx context.Context, target, via string, ttl time.Duration) error
	DeleteRoute(ctx context.Context, target string) error
	Select(ctx context.Context, group, member string) error
	Delay(ctx context.Context, name string) (api.Delay, error)
	SetMode(ctx context.Context, mode string) error
	SetSysProxy(ctx context.Context, on bool) error
	UpdateSubscription(ctx context.Context, name string) error
	Restart(ctx context.Context) error
	Connections(ctx context.Context) ([]daemon.Connection, error)
	CloseConnection(ctx context.Context, id string) error
	Failed(ctx context.Context) ([]daemon.Failed, error)
	ClearFailed(ctx context.Context) error
	Suggest(ctx context.Context, host string) ([]string, error)
	Logs(ctx context.Context) ([]string, error)
	Events(ctx context.Context) (<-chan api.Event, error)
}

type page int

const (
	pageOverview page = iota
	pageOutbounds
	pageRoutes
	pageConns
	pageLogs
	numPages
)

var pageNames = [numPages]string{"概览", "出口", "路由", "连接", "日志"}

const (
	maxLogs    = 1000
	maxSamples = 300
)

// Model is the TUI's state.
type Model struct {
	c   Client
	ctx context.Context

	w, h int
	page page
	help bool

	connected bool
	connErr   string // why the event stream is down
	events    <-chan api.Event
	status    *daemon.Status
	msg       string // the outcome of the last action
	msgBad    bool
	msgUntil  time.Time

	up, down  []int64
	outbounds []daemon.Outbound
	expanded  map[string]bool // groups showing their members
	delays    map[string]delay
	routes    *view.Table
	explain   *explanation
	conns     []daemon.Connection
	connsErr  string
	failed    []daemon.Failed
	logs      []string
	follow    bool // keep the newest log line in view

	lists  [numPages]list
	search *searchBox
	dialog dialog
}

type delay struct {
	pending bool
	ms      int64
	err     string
	hops    []daemon.HopDelay
}

type explanation struct {
	query string
	v     view.Explanation
	err   string
}

// New returns a TUI that talks to c until ctx is done.
func New(ctx context.Context, c Client) *Model {
	return &Model{c: c, ctx: ctx, expanded: map[string]bool{}, delays: map[string]delay{}, follow: true, search: newSearch()}
}

// Run shows the TUI until the user quits.
func Run(ctx context.Context, c Client) error {
	_, err := tea.NewProgram(New(ctx, c), tea.WithContext(ctx)).Run()
	if errors.Is(err, tea.ErrProgramKilled) && ctx.Err() != nil {
		return nil
	}
	return err
}

// Messages carrying API results.
type (
	statusMsg    daemon.Status
	outboundsMsg []daemon.Outbound
	routesMsg    view.Table
	explainMsg   explanation
	connsMsg     struct {
		conns  []daemon.Connection
		failed []daemon.Failed
		err    error
	}
	logsMsg  []string
	delayMsg struct {
		name string
		d    api.Delay
		err  error
	}
	// doneMsg reports a change the user asked for.
	doneMsg struct {
		ok  string
		err error
	}
	suggestMsg struct {
		host    string
		targets []string
		err     error
	}
	connectedMsg    struct{ ch <-chan api.Event }
	disconnectedMsg struct{ err error }
	eventMsg        api.Event
	reconnectMsg    struct{}
	tickMsg         time.Time
)

func (m *Model) Init() tea.Cmd {
	return tea.Batch(m.connect(), tick())
}

func tick() tea.Cmd {
	return tea.Tick(2*time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// call runs an API request off the UI goroutine.
func (m *Model) call(f func(ctx context.Context) tea.Msg) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(m.ctx, 30*time.Second)
		defer cancel()
		return f(ctx)
	}
}

func (m *Model) connect() tea.Cmd {
	return m.call(func(ctx context.Context) tea.Msg {
		ch, err := m.c.Events(m.ctx) // lives as long as the TUI
		if err != nil {
			return disconnectedMsg{err}
		}
		return connectedMsg{ch}
	})
}

func listen(ch <-chan api.Event) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return disconnectedMsg{errors.New("与 daemon 的连接断开了")}
		}
		return eventMsg(ev)
	}
}

func (m *Model) loadStatus() tea.Cmd {
	return m.call(func(ctx context.Context) tea.Msg {
		s, err := m.c.Status(ctx)
		if err != nil {
			return doneMsg{err: err}
		}
		return statusMsg(s)
	})
}

func (m *Model) loadOutbounds() tea.Cmd {
	return m.call(func(ctx context.Context) tea.Msg {
		o, err := m.c.Outbounds(ctx)
		if err != nil {
			return doneMsg{err: err}
		}
		return outboundsMsg(o)
	})
}

func (m *Model) loadRoutes() tea.Cmd {
	return m.call(func(ctx context.Context) tea.Msg {
		t, err := m.c.Routes(ctx)
		if err != nil {
			return doneMsg{err: err}
		}
		return routesMsg(t)
	})
}

func (m *Model) loadConns() tea.Cmd {
	return m.call(func(ctx context.Context) tea.Msg {
		var r connsMsg
		r.conns, r.err = m.c.Connections(ctx)
		r.failed, _ = m.c.Failed(ctx)
		return r
	})
}

func (m *Model) loadLogs() tea.Cmd {
	return m.call(func(ctx context.Context) tea.Msg {
		l, err := m.c.Logs(ctx)
		if err != nil {
			return doneMsg{err: err}
		}
		return logsMsg(l)
	})
}

// refresh reloads what the current page shows.
func (m *Model) refresh() tea.Cmd {
	switch m.page {
	case pageOutbounds:
		return m.loadOutbounds()
	case pageRoutes:
		return tea.Batch(m.loadRoutes(), m.loadOutbounds())
	case pageConns:
		return tea.Batch(m.loadConns(), m.loadOutbounds())
	}
	return nil
}

// do runs a change and reports it; the daemon's state event refreshes the pages.
func (m *Model) do(ok string, f func(ctx context.Context) error) tea.Cmd {
	return m.call(func(ctx context.Context) tea.Msg { return doneMsg{ok: ok, err: f(ctx)} })
}

func (m *Model) testDelay(names ...string) tea.Cmd {
	var cmds []tea.Cmd
	for _, name := range names {
		m.delays[name] = delay{pending: true, hops: m.delays[name].hops}
		cmds = append(cmds, m.call(func(ctx context.Context) tea.Msg {
			d, err := m.c.Delay(ctx, name)
			return delayMsg{name, d, err}
		}))
	}
	return tea.Batch(cmds...)
}

func (m *Model) note(text string, isErr bool) {
	m.msg, m.msgBad, m.msgUntil = text, isErr, time.Now().Add(6*time.Second)
}

// errText explains an API error the way users need to read it.
func errText(err error) string {
	var e *api.APIError
	switch {
	case errors.Is(err, api.ErrNotRunning):
		return "nautilus daemon 没有在运行：先在另一个终端运行 nautilus daemon"
	case errors.As(err, &e) && e.Status == http.StatusUnauthorized:
		return "密码不对：TUI 使用 .env 里的 NAUTILUS_PASSWORD，和 daemon 用的应该是同一个文件"
	case errors.As(err, &e):
		text := e.Error()
		if e.Body.Where != "" {
			text += "（" + e.Body.Where + "）"
		}
		return strings.ReplaceAll(text, "\n", "；")
	case err != nil:
		return err.Error()
	}
	return ""
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		return m, nil
	case tea.KeyPressMsg:
		return m, m.key(msg)
	case connectedMsg:
		m.connected, m.connErr, m.events = true, "", msg.ch
		return m, tea.Batch(listen(msg.ch), m.loadLogs(), m.loadOutbounds(), m.loadRoutes())
	case disconnectedMsg:
		m.connected, m.connErr = false, errText(msg.err)
		return m, tea.Tick(2*time.Second, func(time.Time) tea.Msg { return reconnectMsg{} })
	case reconnectMsg:
		return m, m.connect()
	case eventMsg:
		return m, tea.Batch(m.event(api.Event(msg)), listen(m.events))
	case statusMsg:
		s := daemon.Status(msg)
		m.status = &s
		return m, nil
	case outboundsMsg:
		m.outbounds = msg
		return m, nil
	case routesMsg:
		t := view.Table(msg)
		m.routes = &t
		return m, nil
	case explainMsg:
		e := explanation(msg)
		m.explain = &e
		return m, nil
	case connsMsg:
		m.conns, m.failed, m.connsErr = msg.conns, msg.failed, errText(msg.err)
		return m, nil
	case logsMsg:
		m.logs = append([]string(nil), msg...)
		return m, nil
	case delayMsg:
		d := delay{ms: msg.d.Delay, err: msg.d.Error, hops: msg.d.Hops}
		if msg.err != nil {
			d.err = errText(msg.err)
		}
		m.delays[msg.name] = d
		return m, nil
	case suggestMsg:
		if msg.err != nil {
			m.note(errText(msg.err), true)
			return m, nil
		}
		m.dialog = newRouteDialog(m, "让这个网站走……", msg.host, msg.targets, "")
		return m, nil
	case doneMsg:
		if msg.err != nil {
			m.note(errText(msg.err), true)
		} else if msg.ok != "" {
			m.note(msg.ok, false)
		}
		return m, m.refresh()
	case tickMsg:
		var cmd tea.Cmd
		if m.page == pageConns && m.connected && m.dialog == nil {
			cmd = m.loadConns()
		}
		return m, tea.Batch(cmd, tick())
	}
	return m, nil
}

func (m *Model) event(ev api.Event) tea.Cmd {
	switch ev.Type {
	case "state":
		var s daemon.Status
		if json.Unmarshal(ev.Data, &s) == nil {
			m.status = &s
		}
		return m.refresh()
	case "traffic":
		var t control.Traffic
		if json.Unmarshal(ev.Data, &t) == nil {
			m.up = append(m.up, t.Up)
			m.down = append(m.down, t.Down)
			if len(m.up) > maxSamples {
				m.up, m.down = m.up[1:], m.down[1:]
			}
		}
	case "log":
		var line string
		if json.Unmarshal(ev.Data, &line) == nil {
			m.logs = append(m.logs, line)
			if len(m.logs) > maxLogs {
				m.logs = m.logs[len(m.logs)-maxLogs:]
			}
		}
	}
	return nil
}

func (m *Model) key(k tea.KeyPressMsg) tea.Cmd {
	key := k.String()
	if key == "ctrl+c" {
		return tea.Quit
	}
	if m.dialog != nil {
		return m.dialog.key(m, k)
	}
	if m.search != nil && m.search.focused() {
		return m.search.key(m, k)
	}
	if m.help {
		m.help = false
		return nil
	}
	switch key {
	case "q":
		return tea.Quit
	case "?":
		m.help = true
		return nil
	case "tab":
		return m.show((m.page + 1) % numPages)
	case "shift+tab":
		return m.show((m.page + numPages - 1) % numPages)
	case "1", "2", "3", "4", "5":
		return m.show(page(key[0] - '1'))
	case "ctrl+r", "f5":
		return tea.Batch(m.loadStatus(), m.refresh())
	}
	rows := m.rows()
	l := &m.lists[m.page]
	switch key {
	case "up", "k":
		l.move(rows, -1)
		m.follow = false
	case "down", "j":
		l.move(rows, 1)
	case "pgup":
		l.move(rows, -m.bodyHeight())
		m.follow = false
	case "pgdown":
		l.move(rows, m.bodyHeight())
	case "home", "g":
		l.home()
		m.follow = false
	case "end", "G":
		l.end(rows)
		m.follow = true
	default:
		return m.pageKey(key, l.selected(rows))
	}
	if m.page == pageLogs && l.cursor == len(selectable(rows))-1 {
		m.follow = true
	}
	return nil
}

func (m *Model) show(p page) tea.Cmd {
	m.page = p
	if p == pageLogs && m.follow {
		m.lists[p].end(m.rows())
	}
	return m.refresh()
}

// pageKey handles the keys of the current page for the selected item.
func (m *Model) pageKey(key string, item any) tea.Cmd {
	switch m.page {
	case pageOverview:
		return m.overviewKey(key, item)
	case pageOutbounds:
		return m.outboundsKey(key, item)
	case pageRoutes:
		return m.routesKey(key, item)
	case pageConns:
		return m.connsKey(key, item)
	case pageLogs:
		if key == "f" {
			m.follow = !m.follow
			if m.follow {
				m.lists[pageLogs].end(m.rows())
			}
		}
	}
	return nil
}

func (m *Model) rows() []row {
	w := max(20, m.w)
	switch m.page {
	case pageOverview:
		return m.overviewRows(w)
	case pageOutbounds:
		return m.outboundRows(w)
	case pageRoutes:
		return m.routeRows(w)
	case pageConns:
		return m.connRows(w)
	case pageLogs:
		return m.logRows()
	}
	return nil
}

func (m *Model) bodyHeight() int {
	h := m.h - 3 // tabs, the line under them, the footer
	if m.page == pageRoutes {
		h -= m.searchHeight()
	}
	return max(1, h)
}

func (m *Model) View() tea.View {
	v := tea.NewView(m.render())
	v.AltScreen = true
	v.WindowTitle = "Nautilus"
	return v
}

func (m *Model) render() string {
	if m.w == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(m.header())
	b.WriteString("\n")
	switch {
	case m.dialog != nil:
		b.WriteString(m.dialog.view(m, m.w, m.h-3))
	case m.help:
		b.WriteString(m.helpView(m.h - 3))
	default:
		if m.page == pageRoutes {
			b.WriteString(m.searchView(m.w))
		}
		rows := m.rows()
		if m.page == pageLogs && m.follow {
			m.lists[pageLogs].end(rows)
		}
		body := m.lists[m.page].render(rows, m.w, m.bodyHeight())
		b.WriteString(body)
		b.WriteString(strings.Repeat("\n", max(0, m.bodyHeight()-strings.Count(body, "\n")-1)))
	}
	b.WriteString("\n")
	b.WriteString(m.footer())
	return b.String()
}

func (m *Model) header() string {
	var tabs []string
	for i, name := range pageNames {
		label := fmt.Sprintf("%d %s", i+1, name)
		if page(i) == m.page {
			tabs = append(tabs, tabOn.Render(label))
		} else {
			tabs = append(tabs, tabOff.Render(label))
		}
	}
	left := bold.Render("Nautilus") + " " + strings.Join(tabs, "")
	var right string
	switch {
	case !m.connected:
		right = bad.Render("未连接")
	case m.status != nil:
		s := m.status
		state := stateNames[string(s.Kernel.State)]
		style := good
		if s.Kernel.State != "running" {
			style = warn
		}
		right = style.Render(s.Backend+" "+state) + muted.Render(" · ") + modeName(s.Mode)
		if s.SysProxy {
			right += muted.Render(" · ") + "系统代理"
		}
	}
	return spread(left, right, m.w) + "\n" + muted.Render(strings.Repeat("─", m.w))
}

func modeName(mode string) string {
	return map[string]string{"rule": "分流", "global": "全局", "direct": "直连"}[mode]
}

func (m *Model) footer() string {
	if m.msg != "" && time.Now().Before(m.msgUntil) {
		if m.msgBad {
			return bad.Render(truncate(m.msg, m.w))
		}
		return good.Render(truncate(m.msg, m.w))
	}
	if !m.connected && m.connErr != "" {
		return bad.Render(truncate(m.connErr+"（正在重试）", m.w))
	}
	var hints string
	switch {
	case m.dialog != nil:
		hints = m.dialog.hints()
	case m.search != nil && m.search.focused():
		hints = "enter 查询 · esc 取消"
	default:
		hints = m.pageHints() + " · ? 帮助 · q 退出"
	}
	return muted.Render(truncate(hints, m.w))
}

func (m *Model) pageHints() string {
	switch m.page {
	case pageOverview:
		return "m 切换模式 · s 系统代理 · u 更新订阅 · R 重启内核"
	case pageOutbounds:
		return "enter 展开/选择 · t 测速"
	case pageRoutes:
		return "/ 这个地址怎么走 · a 添加 · e 改出口 · d 删除"
	case pageConns:
		return "r 给这个网站指定出口 · x 断开 · c 清空失败记录"
	case pageLogs:
		follow := "f 跟随最新"
		if m.follow {
			follow = "f 停止跟随"
		}
		return follow + " · G 到底部"
	}
	return ""
}

func (m *Model) helpView(h int) string {
	lines := []string{
		titleStyle.Render("按键"),
		"  1-5 / tab    切换页面",
		"  ↑↓ / j k     移动光标；pgup pgdown 翻页；g G 到顶/底",
		"  ctrl+r       刷新",
		"  q / ctrl+c   退出",
		"",
		titleStyle.Render("概览"),
		"  m 切换分流模式 · s 开关系统代理 · u 更新选中的订阅 · R 重启内核",
		titleStyle.Render("出口"),
		"  enter 展开出口组或选择成员 · t 测速（出口组：测所有成员；链：逐跳测速）",
		titleStyle.Render("路由"),
		"  / 查询一个地址会怎么走 · a 添加条目 · e 修改选中条目的出口 · d 删除选中的条目",
		titleStyle.Render("连接"),
		"  r 给选中的网站指定出口 · x 断开连接 · c 清空加载失败的记录",
		"",
		muted.Render("按任意键返回"),
	}
	if len(lines) > h {
		lines = lines[:h]
	}
	return strings.Join(lines, "\n") + strings.Repeat("\n", max(0, h-len(lines)))
}
