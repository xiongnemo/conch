package nodeform

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Parse reads nodes written as in a profile: one mapping, a list of
// them, or a document with nodes:.
func Parse(text string) ([]*yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return nil, fmt.Errorf("YAML 写错了：%s", strings.TrimPrefix(err.Error(), "yaml: "))
	}
	if len(doc.Content) == 0 {
		return nil, errors.New("没有写节点")
	}
	root := doc.Content[0]
	if root.Kind == yaml.MappingNode {
		if list := lookup(root, "nodes"); list != nil {
			root = list
		} else {
			return []*yaml.Node{root}, nil
		}
	}
	if root.Kind != yaml.SequenceNode {
		return nil, errors.New("节点要写成 { name: …, type: …, server: …, port: … } 这样的映射")
	}
	for _, n := range root.Content {
		if n.Kind != yaml.MappingNode {
			return nil, errors.New("列表里的每一项都要是 { name: …, type: … } 这样的映射")
		}
	}
	if len(root.Content) == 0 {
		return nil, errors.New("没有写节点")
	}
	return root.Content, nil
}

// FromJSON reads a node the form sent; JSON is YAML, and the order of
// its keys is kept.
func FromJSON(data []byte) (*yaml.Node, error) {
	nodes, err := Parse(string(data))
	if err != nil {
		return nil, err
	}
	if len(nodes) != 1 {
		return nil, errors.New("一次只能填一个节点")
	}
	return nodes[0], nil
}

// Tidy writes a node the way managed.yaml keeps it: the form's keys in
// the form's order, then the rest as they were, without empty values.
func Tidy(n *yaml.Node) *yaml.Node {
	out := &yaml.Node{Kind: yaml.MappingNode}
	var order []string
	for _, f := range Fields {
		top, _, _ := strings.Cut(f.Key, ".")
		if !slices.Contains(order, top) {
			order = append(order, top)
		}
	}
	type pair struct{ k, v *yaml.Node }
	var known, rest []pair
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], prune(n.Content[i+1])
		if v == nil {
			continue
		}
		v.Style &^= yaml.FlowStyle
		if slices.Contains(order, k.Value) {
			known = append(known, pair{k, v})
		} else {
			rest = append(rest, pair{k, v})
		}
	}
	slices.SortStableFunc(known, func(a, b pair) int {
		return slices.Index(order, a.k.Value) - slices.Index(order, b.k.Value)
	})
	for _, p := range append(known, rest...) {
		out.Content = append(out.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: p.k.Value}, p.v)
	}
	return out
}

// prune drops empty values: empty strings, nulls, and mappings and lists
// left empty without them. Strings are kept as they are, quoted only
// when they must be.
func prune(v *yaml.Node) *yaml.Node {
	switch v.Kind {
	case yaml.ScalarNode:
		if v.Tag == "!!null" || v.Tag == "!!str" && v.Value == "" {
			return nil
		}
		c := *v
		if c.Tag == "!!str" {
			c.Style = 0
			if !isPlainString(c.Value) {
				c.Style = yaml.DoubleQuotedStyle
			}
		}
		return &c
	case yaml.MappingNode, yaml.SequenceNode:
		c := *v
		c.Content = nil
		step := 1
		if v.Kind == yaml.MappingNode {
			step = 2
		}
		for i := 0; i+step-1 < len(v.Content); i += step {
			item := prune(v.Content[i+step-1])
			if item == nil {
				continue
			}
			if step == 2 {
				c.Content = append(c.Content, v.Content[i])
			}
			c.Content = append(c.Content, item)
		}
		if len(c.Content) == 0 {
			return nil
		}
		return &c
	case yaml.AliasNode:
		return prune(v.Alias)
	}
	return v
}

// isPlainString reports whether s reads back as the same string unquoted.
func isPlainString(s string) bool {
	var back any
	if err := yaml.Unmarshal([]byte(s), &back); err != nil {
		return false
	}
	got, ok := back.(string)
	return ok && got == s && !strings.ContainsAny(s, "{}[],#&*!|>'\"%@`")
}

// Line writes a node on one line, as managed.yaml has it.
func Line(n *yaml.Node) string {
	c := *n
	c.Style = yaml.FlowStyle
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.Encode(&c)
	enc.Close()
	return strings.TrimSpace(buf.String())
}

// ToMap is a node as the form edits it.
func ToMap(n *yaml.Node) (map[string]any, error) {
	var m map[string]any
	if err := n.Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}

// Name is a node's name, as written.
func Name(n *yaml.Node) string {
	if v := lookup(n, "name"); v != nil && v.Kind == yaml.ScalarNode {
		return strings.TrimSpace(v.Value)
	}
	return ""
}

// Missing lists the required fields a node has no value for.
func Missing(n *yaml.Node) []string {
	m, err := ToMap(n)
	if err != nil {
		return nil
	}
	var out []string
	for _, f := range Fields {
		if f.Required && Visible(f, m) && Text(Get(m, f.Key)) == "" && !slices.Contains(out, f.Label) {
			out = append(out, f.Label)
		}
	}
	return out
}

func lookup(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// Get finds a field's value by its dotted key.
func Get(m map[string]any, key string) any {
	var cur any = m
	for _, part := range strings.Split(key, ".") {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[part]
	}
	return cur
}

// Set gives a field a value by its dotted key; nil removes it, and
// mappings left empty with it.
func Set(m map[string]any, key string, v any) {
	parts := strings.Split(key, ".")
	cur := m
	for _, part := range parts[:len(parts)-1] {
		next, ok := cur[part].(map[string]any)
		if !ok {
			if v == nil {
				return
			}
			next = map[string]any{}
			cur[part] = next
		}
		cur = next
	}
	if v == nil {
		delete(cur, parts[len(parts)-1])
	} else {
		cur[parts[len(parts)-1]] = v
	}
}

// Text is a value as a form input shows it: lists comma separated.
func Text(v any) string {
	switch v := v.(type) {
	case nil:
		return ""
	case string:
		return v
	case []any:
		parts := make([]string, len(v))
		for i, x := range v {
			parts[i] = Text(x)
		}
		return strings.Join(parts, ", ")
	case bool:
		return strconv.FormatBool(v)
	default:
		return fmt.Sprint(v)
	}
}

// Value is what an input's text means for a field of the kind: nil for
// nothing, so the key goes away.
func Value(f Field, text string) any {
	if f.Kind != "secret" {
		text = strings.TrimSpace(text)
	}
	switch {
	case text == "":
		return nil
	case f.Kind == "number":
		if n, err := strconv.Atoi(text); err == nil {
			return n
		}
		return text
	case f.Kind == "bool":
		return text == "true"
	case f.Kind == "list":
		var out []any
		for _, part := range strings.FieldsFunc(text, func(r rune) bool { return r == ',' || r == '，' }) {
			if part = strings.TrimSpace(part); part != "" {
				if n, err := strconv.Atoi(part); err == nil && f.Key == "reserved" {
					out = append(out, n)
				} else {
					out = append(out, part)
				}
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	}
	return text
}

// Visible reports whether a field shows for a node: it belongs to the
// node's protocol, and the fields it depends on have the values it needs.
func Visible(f Field, m map[string]any) bool {
	if len(f.Types) > 0 && !slices.Contains(f.Types, Text(m["type"])) {
		return false
	}
	for key, values := range f.When {
		if !slices.Contains(values, Text(Get(m, key))) {
			return false
		}
	}
	return true
}

// New is a node of a protocol with the form's defaults.
func New(typ string) map[string]any {
	m := map[string]any{"type": typ}
	for _, f := range Fields {
		if f.Default != nil && Visible(f, m) {
			Set(m, f.Key, f.Default)
		}
	}
	return m
}
