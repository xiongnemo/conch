package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"charm.land/bubbles/v2/textarea"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"

	"github.com/xiongnemo/conch/internal/daemon"
	"github.com/xiongnemo/conch/internal/nodeform"
)

// nodeDialog adds nodes three ways: from share links, in a form whose
// fields follow the protocol, or as profile YAML; and edits a node
// conch added, in the last two. The form and the YAML are the same node:
// switching carries it over. The daemon checks what is typed for the
// running kernel, a moment after the typing stops.
type nodeDialog struct {
	mode    int // nodeLink, nodeForm, nodeYAML
	editing string

	link textinput.Model
	yaml textarea.Model

	node   map[string]any
	more   bool
	cursor int             // the form's row
	input  textinput.Model // the text of the row the cursor is on

	// written is nodeForm or nodeYAML when what was written there last
	// is not in the other yet, -1 when they agree.
	written int

	check   daemon.NodeCheck
	seq     int  // changes so far; a check is of the latest
	ticking bool // a check is due
	problem string
}

const (
	nodeLink = iota
	nodeForm
	nodeYAML
)

var nodeModes = []string{"分享链接", "表单", "profile 写法"}

// nodeCheckTick asks for a check when nothing changed since it was set.
type nodeCheckTick struct{ seq int }

type nodeCheckMsg struct {
	seq int
	c   daemon.NodeCheck
	err error
}

type nodeSavedMsg struct {
	names []string
	err   error
}

// nodeLoadedMsg is a node fetched for editing.
type nodeLoadedMsg struct {
	name string
	v    daemon.NodeView
	err  error
}

func newNodeDialog() *nodeDialog {
	d := &nodeDialog{link: textinput.New(), yaml: textarea.New(), input: textinput.New(), node: nodeform.New(nodeform.Types[0].Value), written: -1}
	d.link.Prompt, d.input.Prompt = "", ""
	// A steady cursor: it moves between many fields.
	for _, in := range []*textinput.Model{&d.link, &d.input} {
		st := in.Styles()
		st.Cursor.Blink = false
		in.SetStyles(st)
	}
	d.link.Focus()
	d.yaml.ShowLineNumbers = false
	d.yaml.Prompt = ""
	d.yaml.Placeholder = "{ name: 香港 01, type: ss, server: hk.example.com, port: 8388, cipher: aes-128-gcm, password: … }"
	plain := textarea.StyleState{Placeholder: muted}
	cur := textarea.DefaultStyles(true).Cursor
	cur.Blink = false
	d.yaml.SetStyles(textarea.Styles{Focused: plain, Blurred: plain, Cursor: cur})
	d.yaml.SetHeight(5)
	return d
}

// editNodeDialog edits a node conch added, in the form.
func editNodeDialog(name string, v daemon.NodeView) *nodeDialog {
	d := newNodeDialog()
	d.editing, d.node = name, v.Node
	d.yaml.SetValue(v.YAML)
	d.setMode(nodeForm)
	return d
}

// rows are the form's fields that show; folded ones only when asked for
// or when they have a value. -1 stands for the row that unfolds them.
func (d *nodeDialog) rows() []int {
	var rows []int
	folded := 0
	for i, f := range nodeform.Fields {
		if !nodeform.Visible(f, d.node) {
			continue
		}
		if f.More && !d.more && nodeform.Get(d.node, f.Key) == nil {
			folded++
			continue
		}
		rows = append(rows, i)
	}
	if folded > 0 || d.more {
		rows = append(rows, -1)
	}
	return rows
}

func (d *nodeDialog) field() (nodeform.Field, bool) {
	rows := d.rows()
	d.cursor = min(max(d.cursor, 0), len(rows)-1)
	if rows[d.cursor] < 0 {
		return nodeform.Field{}, false
	}
	return nodeform.Fields[rows[d.cursor]], true
}

// focus puts the text of the field under the cursor in the input.
func (d *nodeDialog) focus() {
	f, ok := d.field()
	if !ok || f.Kind == "bool" || f.Kind == "select" {
		d.input.Blur()
		return
	}
	d.input.SetValue(nodeform.Text(nodeform.Get(d.node, f.Key)))
	d.input.CursorEnd()
	d.input.Focus()
}

// set changes a field. A change of protocol brings the new one's
// defaults; one that shows or hides fields drops the hidden ones' values.
func (d *nodeDialog) set(f nodeform.Field, v any) tea.Cmd {
	key := f.Key
	d.written = nodeForm
	nodeform.Set(d.node, key, v)
	if key == "type" {
		for _, x := range nodeform.Fields {
			if x.Default != nil && nodeform.Get(d.node, x.Key) == nil && nodeform.Visible(x, d.node) {
				nodeform.Set(d.node, x.Key, x.Default)
			}
		}
	}
	if decides(key) {
		shown := map[string]bool{}
		for _, x := range nodeform.Fields {
			if nodeform.Visible(x, d.node) {
				shown[x.Key] = true
			}
		}
		for _, x := range nodeform.Fields {
			if !shown[x.Key] {
				nodeform.Set(d.node, x.Key, nil)
			}
		}
		// Keep the cursor on the field that changed.
		if i := slices.IndexFunc(d.rows(), func(r int) bool { return r >= 0 && nodeform.Fields[r].Key == key }); i >= 0 {
			d.cursor = i
		}
	}
	return d.checkSoon()
}

func decides(key string) bool {
	if key == "type" {
		return true
	}
	for _, f := range nodeform.Fields {
		if _, ok := f.When[key]; ok {
			return true
		}
	}
	return false
}

// input is what is typed, for the daemon.
func (d *nodeDialog) nodeInput() daemon.NodeInput {
	if d.mode == nodeYAML {
		return daemon.NodeInput{YAML: d.yaml.Value()}
	}
	b, _ := json.Marshal(d.node)
	return daemon.NodeInput{Node: b}
}

// checkSoon has the daemon check what is written once the typing
// stops: one timer at a time, set again when it finds more typed.
func (d *nodeDialog) checkSoon() tea.Cmd {
	d.seq++
	d.problem = ""
	if d.ticking {
		return nil
	}
	d.ticking = true
	return d.tick()
}

func (d *nodeDialog) tick() tea.Cmd {
	seq := d.seq
	return tea.Tick(400*time.Millisecond, func(time.Time) tea.Msg { return nodeCheckTick{seq} })
}

// setMode switches how the node is written, carrying over what was
// written last; YAML the form cannot hold keeps it from the form.
func (d *nodeDialog) setMode(mode int) bool {
	switch {
	case mode == nodeYAML && d.written == nodeForm:
		if !reflect.DeepEqual(d.node, nodeform.New(nodeform.Text(d.node["type"]))) {
			if n, err := nodeform.FromJSON(d.nodeInput().Node); err == nil {
				d.yaml.SetValue(nodeform.Line(nodeform.Tidy(n)) + "\n")
			}
		}
	case mode == nodeForm && d.written == nodeYAML && strings.TrimSpace(d.yaml.Value()) != "":
		nodes, err := nodeform.Parse(d.yaml.Value())
		if err != nil {
			d.problem = "表单装不下：" + err.Error()
			return false
		}
		if len(nodes) > 1 {
			d.problem = fmt.Sprintf("profile 写法里有 %d 个节点，表单一次只能填一个；请在那里保存", len(nodes))
			return false
		}
		m, err := nodeform.ToMap(nodeform.Tidy(nodes[0]))
		if err != nil {
			d.problem = err.Error()
			return false
		}
		d.node = m
	}
	if mode != nodeLink {
		d.written = -1
	}
	d.mode, d.problem, d.check = mode, "", daemon.NodeCheck{}
	d.link.Blur()
	d.yaml.Blur()
	d.input.Blur()
	switch mode {
	case nodeLink:
		d.link.Focus()
	case nodeForm:
		d.focus()
	case nodeYAML:
		d.yaml.Focus()
	}
	return true
}

func (d *nodeDialog) update(m *Model, msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case nodeCheckTick:
		if msg.seq != d.seq {
			return d.tick() // still typing
		}
		d.ticking = false
		if d.mode == nodeLink || d.mode == nodeYAML && strings.TrimSpace(d.yaml.Value()) == "" {
			return nil
		}
		in, editing := d.nodeInput(), d.editing
		return m.call(func(ctx context.Context) tea.Msg {
			c, err := m.c.CheckNodes(ctx, in, editing)
			return nodeCheckMsg{msg.seq, c, err}
		})
	case nodeCheckMsg:
		if msg.seq == d.seq {
			d.check = msg.c
			if msg.err != nil {
				d.check = daemon.NodeCheck{Errors: []string{errText(msg.err)}}
			}
		}
	case nodeSavedMsg:
		if msg.err != nil {
			d.problem = errText(msg.err)
			return nil
		}
		m.dialog = nil
		verb := "已添加"
		if d.editing != "" {
			verb = "已保存"
		}
		m.note(verb+"节点 "+strings.Join(msg.names, "、"), false)
		return m.refresh()
	}
	return nil
}

func (d *nodeDialog) save(m *Model) tea.Cmd {
	if d.mode == nodeLink {
		link := strings.TrimSpace(d.link.Value())
		if link == "" {
			return nil
		}
		m.dialog = nil
		return m.call(func(ctx context.Context) tea.Msg {
			added, err := m.c.AddNodes(ctx, link)
			return doneMsg{ok: added.Summary(), err: err}
		})
	}
	in, editing := d.nodeInput(), d.editing
	d.problem = "保存中……"
	return m.call(func(ctx context.Context) tea.Msg {
		names, err := m.c.SaveNodes(ctx, in, editing)
		return nodeSavedMsg{names, err}
	})
}

func (d *nodeDialog) key(m *Model, k tea.KeyPressMsg) tea.Cmd {
	switch k.String() {
	case "esc":
		m.dialog = nil
		return nil
	case "ctrl+s":
		return d.save(m)
	case "ctrl+t":
		// The next way of writing that can take the node; the form is
		// skipped when the YAML has more than it holds, saying why.
		why := ""
		for i := 1; i < len(nodeModes); i++ {
			next := (d.mode + i) % len(nodeModes)
			if d.editing != "" && next == nodeLink {
				continue
			}
			if d.setMode(next) {
				break
			}
			why = d.problem
		}
		cmd := d.checkSoon()
		d.problem = why
		return cmd
	}
	switch d.mode {
	case nodeLink:
		if k.String() == "enter" {
			return d.save(m)
		}
		var cmd tea.Cmd
		d.link, cmd = d.link.Update(k)
		return cmd
	case nodeYAML:
		before := d.yaml.Value()
		var cmd tea.Cmd
		d.yaml, cmd = d.yaml.Update(k)
		if d.yaml.Value() != before {
			d.written = nodeYAML
			return tea.Batch(cmd, d.checkSoon())
		}
		return cmd
	}
	return d.formKey(k)
}

func (d *nodeDialog) formKey(k tea.KeyPressMsg) tea.Cmd {
	rows := d.rows()
	move := func(by int) tea.Cmd {
		d.cursor = min(max(d.cursor+by, 0), len(rows)-1)
		d.focus()
		return nil
	}
	f, isField := d.field()
	switch k.String() {
	case "up", "shift+tab":
		return move(-1)
	case "down", "tab", "enter":
		if !isField && k.String() == "enter" {
			d.more = !d.more
			d.focus()
			return nil
		}
		return move(1)
	}
	if !isField {
		if k.String() == "space" {
			d.more = !d.more
			d.focus()
		}
		return nil
	}
	switch f.Kind {
	case "bool":
		if k.String() == "space" || k.String() == "left" || k.String() == "right" {
			on := nodeform.Get(d.node, f.Key) == true
			var v any
			if !on {
				v = true
			}
			return d.set(f, v)
		}
		return nil
	case "select":
		by := map[string]int{"left": -1, "h": -1, "right": 1, "l": 1, "space": 1}[k.String()]
		if by == 0 {
			return nil
		}
		cur := slices.IndexFunc(f.Options, func(o nodeform.Option) bool { return o.Value == nodeform.Text(nodeform.Get(d.node, f.Key)) })
		next := f.Options[(cur+by+len(f.Options))%len(f.Options)].Value
		if cur < 0 && by < 0 {
			next = f.Options[len(f.Options)-1].Value
		}
		var v any = next
		if next == "" {
			v = nil
		}
		return d.set(f, v)
	}
	before := d.input.Value()
	var cmd tea.Cmd
	d.input, cmd = d.input.Update(k)
	if d.input.Value() != before {
		return tea.Batch(cmd, d.set(f, nodeform.Value(f, d.input.Value())))
	}
	return cmd
}

func (d *nodeDialog) view(_ *Model, w, h int) string {
	inner := max(40, min(84, w-6))
	title := "添加节点"
	if d.editing != "" {
		title = "修改节点 " + d.editing
	}
	var tabs []string
	for i, name := range nodeModes {
		switch {
		case i == d.mode:
			tabs = append(tabs, tabOn.Render(name))
		case d.editing != "" && i == nodeLink:
		default:
			tabs = append(tabs, tabOff.Render(name))
		}
	}
	lines := []string{bold.Render(title) + "  " + strings.Join(tabs, ""), ""}
	switch d.mode {
	case nodeLink:
		lines = append(lines, inputView(&d.link, "粘贴分享链接，可以一次粘贴多条：vmess://、vless://、ss://、trojan://……", inner))
	case nodeForm:
		lines = append(lines, d.formView(inner, max(4, h-14))...)
	case nodeYAML:
		d.yaml.SetWidth(inner)
		lines = append(lines, d.yaml.View(), muted.Render(truncate("和 profile.yaml 里 nodes: 下的写法一样；可以一次写多个节点（每个一行，前面加 - ）", inner)))
	}
	var notes []string
	for _, e := range d.check.Errors {
		notes = append(notes, bad.Render(truncate("✗ "+e, inner)))
	}
	for _, x := range d.check.Warnings {
		notes = append(notes, warn.Render(truncate("! "+x, inner)))
	}
	if d.problem != "" {
		for _, p := range strings.Split(d.problem, "\n") {
			notes = append(notes, bad.Render(truncate(p, inner)))
		}
	}
	if d.mode == nodeForm && d.check.YAML != "" {
		notes = append(notes, muted.Render(truncate(strings.TrimSpace(d.check.YAML), inner)))
	}
	if len(notes) > 0 {
		lines = append(lines, "")
		lines = append(lines, notes...)
	}
	lines = append(lines, "", muted.Render(d.hints()))
	return centered(strings.Join(lines, "\n"), w, h)
}

// formView draws the rows that fit around the cursor.
func (d *nodeDialog) formView(w, room int) []string {
	rows := d.rows()
	d.cursor = min(max(d.cursor, 0), len(rows)-1)
	start := min(max(0, d.cursor-room/2), max(0, len(rows)-room))
	end := min(len(rows), start+room)
	labelW := 0
	for _, r := range rows {
		if r >= 0 {
			labelW = max(labelW, width(nodeform.Fields[r].Label)+2)
		}
	}
	var out []string
	if start > 0 {
		out = append(out, muted.Render("  ↑ 还有 "+fmt.Sprint(start)+" 项"))
	}
	for i := start; i < end; i++ {
		on := i == d.cursor
		if rows[i] < 0 {
			text := "更多选项"
			if d.more {
				text = "收起更多选项"
			}
			if on {
				text = cursorRow.Render(text)
			}
			out = append(out, "  "+accent.Render("+ ")+text)
			continue
		}
		f := nodeform.Fields[rows[i]]
		label := f.Label
		if f.Required {
			label += bad.Render("*")
		}
		label = fit(label, labelW)
		if on {
			label = cursorRow.Render(label)
		}
		out = append(out, "  "+label+" "+d.valueView(f, on, w-labelW-3))
	}
	if end < len(rows) {
		out = append(out, muted.Render("  ↓ 还有 "+fmt.Sprint(len(rows)-end)+" 项"))
	}
	return out
}

func (d *nodeDialog) valueView(f nodeform.Field, on bool, w int) string {
	v := nodeform.Get(d.node, f.Key)
	switch f.Kind {
	case "bool":
		if v == true {
			return accent.Render("[✓]")
		}
		return "[ ]"
	case "select":
		label := nodeform.Text(v)
		for _, o := range f.Options {
			if o.Value == label {
				label = o.Label
			}
		}
		if on {
			return accent.Render("‹ " + label + " ›")
		}
		return label
	}
	if on {
		d.input.EchoMode = textinput.EchoNormal
		return inputView(&d.input, f.Hint, w)
	}
	text := nodeform.Text(v)
	if text == "" {
		return muted.Render(truncate(f.Hint, w))
	}
	if f.Kind == "secret" {
		return strings.Repeat("•", min(8, len([]rune(text))))
	}
	return truncate(text, w)
}

func (d *nodeDialog) hints() string {
	switch d.mode {
	case nodeLink:
		return "enter 添加 · ctrl+t 换写法 · esc 取消"
	case nodeYAML:
		return "ctrl+s 保存 · ctrl+t 换写法 · esc 取消"
	}
	return "↑↓ 换项 · ←→ 换选项 · space 开关 · ctrl+s 保存 · ctrl+t 换写法 · esc 取消"
}
