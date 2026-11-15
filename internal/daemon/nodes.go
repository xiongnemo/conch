package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/xiongnemo/conch/internal/backend"
	"github.com/xiongnemo/conch/internal/compile"
	"github.com/xiongnemo/conch/internal/diag"
	"github.com/xiongnemo/conch/internal/model"
	"github.com/xiongnemo/conch/internal/nodeform"
	"github.com/xiongnemo/conch/internal/sidecar"
)

// Nodes written by hand, in the form or as YAML, go to managed.yaml like
// nodes from share links. Before they are saved they can be checked:
// tidied the way they will be written, and compiled for the running
// kernel alone, so its errors and warnings show while they are typed.

// NodeCheck is what the UIs show about nodes being written.
type NodeCheck struct {
	Nodes    []map[string]any `json:"nodes"`
	YAML     string           `json:"yaml"` // as managed.yaml will have them
	Errors   []string         `json:"errors,omitempty"`
	Warnings []string         `json:"warnings,omitempty"`
}

// NodeInput is nodes written by hand: the form's one node, or YAML.
type NodeInput struct {
	Node json.RawMessage `json:"node,omitempty"`
	YAML string          `json:"yaml,omitempty"`
}

// Parse reads the nodes an input has.
func (in NodeInput) Parse() ([]*yaml.Node, error) {
	switch {
	case len(in.Node) > 0:
		n, err := nodeform.FromJSON(in.Node)
		if err != nil {
			return nil, err
		}
		return []*yaml.Node{n}, nil
	case strings.TrimSpace(in.YAML) != "":
		return nodeform.Parse(in.YAML)
	}
	return nil, errors.New("没有写节点")
}

// CheckNodes tidies nodes and says what is wrong with them, and what the
// running kernel would warn about, without saving anything. editing is
// the managed node they replace, whose name they may keep.
func (d *Daemon) CheckNodes(nodes []*yaml.Node, editing string) NodeCheck {
	var c NodeCheck
	var lines []string
	seen := map[string]bool{}
	for _, raw := range nodes {
		n := nodeform.Tidy(raw)
		m, err := nodeform.ToMap(n)
		if err != nil {
			c.Errors = append(c.Errors, err.Error())
			continue
		}
		c.Nodes = append(c.Nodes, m)
		lines = append(lines, nodeform.Line(n))
		name := nodeform.Name(n)
		label := fmt.Sprintf("节点 %q", name)
		if name == "" {
			label = "节点"
		}
		if missing := nodeform.Missing(n); len(missing) > 0 {
			c.Errors = append(c.Errors, fmt.Sprintf("%s还要填：%s", label, strings.Join(missing, "、")))
			continue
		}
		switch {
		case seen[name]:
			c.Errors = append(c.Errors, fmt.Sprintf("有两个节点都叫 %q", name))
		case name != editing && d.nameTaken(name):
			c.Errors = append(c.Errors, fmt.Sprintf("已经有叫 %q 的出口了", name))
		}
		seen[name] = true
		errs, warns := d.compileNode(n)
		c.Errors, c.Warnings = append(c.Errors, errs...), append(c.Warnings, warns...)
	}
	if len(lines) == 1 {
		c.YAML = lines[0] + "\n"
	} else if len(lines) > 1 {
		c.YAML = "- " + strings.Join(lines, "\n- ") + "\n"
	}
	return c
}

func (d *Daemon) nameTaken(name string) bool {
	_, ok := definedName(d.loadedProfile(), name)
	return ok || d.hasOutbound(name) || slices.Contains([]string{"DIRECT", "REJECT", "GLOBAL"}, name)
}

// compileNode compiles a profile of just the node for the running
// kernel, and returns what it said, without positions: they would be in
// a file nobody sees.
func (d *Daemon) compileNode(n *yaml.Node) (errs, warns []string) {
	name := nodeform.Name(n)
	doc := &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{
		model.Str("nodes"), {Kind: yaml.SequenceNode, Content: []*yaml.Node{n}},
		model.Str("routes"), {Kind: yaml.MappingNode, Content: []*yaml.Node{model.Str("default"), model.Str(name)}},
	}}
	text, err := yaml.Marshal(doc)
	if err != nil {
		return []string{err.Error()}, nil
	}
	p, err := model.Parse(text, "节点")
	if err != nil {
		return []string{err.Error()}, nil
	}
	res := compile.Compile(p)
	diags := res.Diags
	switch {
	case diags.HasErrors():
	case len(res.Proxies) > 0 && sidecar.Needs(res.Proxies[0], d.backend.Capabilities().TrojanSS):
		_, _, warns, err := sidecar.TrojanGoConfig(res.Proxies[0].Node, sidecar.Ports{Local: 1}, "", nil)
		if err != nil {
			diags.Errorf(diag.Pos{}, "%v", err)
		}
		for _, w := range warns {
			diags.Warnf(diag.Pos{}, "%s", w)
		}
	default:
		diags = append(diags, backend.Check(res, d.backend.Capabilities(), d.backend.Name())...)
		if !diags.HasErrors() {
			_, more := d.backend.Encode(res, backend.Options{Certs: d.certs.Lookup})
			diags = append(diags, more...)
		}
	}
	for _, x := range diags {
		msg := strings.TrimPrefix(x.Msg, fmt.Sprintf("节点 %q：", name))
		if x.Severity == diag.Error {
			errs = append(errs, msg)
		} else {
			warns = append(warns, msg)
		}
	}
	return errs, warns
}

// SaveNodes adds nodes written by hand to managed.yaml, or with editing
// set, puts the one node in place of that managed node, renaming it in
// the groups, chains and entries managed.yaml has. Nodes with errors are
// not saved; a node the kernel then rejects is taken back.
func (d *Daemon) SaveNodes(ctx context.Context, nodes []*yaml.Node, editing string) ([]string, error) {
	if editing != "" {
		if pos, ok := definedName(d.loadedProfile(), editing); ok {
			return nil, &ErrUserFile{What: fmt.Sprintf("节点 %q ", editing), Where: pos.String()}
		}
		if len(nodes) != 1 {
			return nil, errors.New("修改节点时只能写一个节点")
		}
	}
	c := d.CheckNodes(nodes, editing)
	if len(c.Errors) > 0 {
		return nil, errors.New(strings.Join(c.Errors, "\n"))
	}
	var names []string
	err := d.changeManaged(ctx, func(m *managed) error {
		for _, raw := range nodes {
			n := model.NewNode(nodeform.Tidy(raw), diag.Pos{})
			names = append(names, n.Name)
			if editing == "" {
				if managedNode(m, n.Name) != nil || managedChain(m, n.Name) || managedGroup(m, n.Name) {
					return fmt.Errorf("已经有叫 %q 的出口了", n.Name)
				}
				m.Nodes = append(m.Nodes, n)
				continue
			}
			i := slices.IndexFunc(m.Nodes, func(x *model.Node) bool { return x.Name == editing })
			if i < 0 {
				return fmt.Errorf("节点 %q 不是用 conch 添加的，不能在这里修改", editing)
			}
			m.Nodes[i] = n
			if n.Name != editing {
				m.rename(editing, n.Name)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return names, nil
}

// rename points what managed.yaml has at an outbound to its new name.
func (m *managed) rename(from, to string) {
	for _, g := range m.Groups {
		for i, member := range g.Members {
			if member == from {
				g.Members[i] = to
			}
		}
	}
	for _, c := range m.Chains {
		for i, hop := range c.Hops {
			if hop == from {
				c.Hops[i] = to
			}
		}
	}
	for i, e := range m.Entries {
		if e.Via == from {
			m.Entries[i].Via = to
		}
	}
}

// NodeView is a node as written, for the form.
type NodeView struct {
	Node    map[string]any `json:"node"`
	YAML    string         `json:"yaml"`
	Managed bool           `json:"managed"` // added with conch, so it can be changed
}

// Node finds a node as written: in managed.yaml, which can be changed,
// or anywhere else the running config has it from.
func (d *Daemon) Node(name string) (NodeView, error) {
	if m, err := loadManaged(d.managedPath()); err == nil {
		if n := managedNode(m, name); n != nil {
			return nodeView(n.Raw, true)
		}
	}
	d.mu.Lock()
	res := d.res
	d.mu.Unlock()
	if res != nil {
		for _, p := range res.Proxies {
			if p.Kind == compile.ProxyNode && p.Name == name {
				return nodeView(p.Node.Raw, false)
			}
		}
	}
	return NodeView{}, fmt.Errorf("节点 %q %w", name, ErrNotFound)
}

func nodeView(raw *yaml.Node, managed bool) (NodeView, error) {
	n := nodeform.Tidy(raw)
	m, err := nodeform.ToMap(n)
	if err != nil {
		return NodeView{}, err
	}
	return NodeView{Node: m, YAML: nodeform.Line(n) + "\n", Managed: managed}, nil
}
