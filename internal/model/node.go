package model

import (
	"fmt"

	"go.yaml.in/yaml/v3"

	"nautilus/internal/diag"
)

// NativeFormat identifies how a node was originally written. A backend that
// speaks the same format can emit the node losslessly.
type NativeFormat int

const (
	// FormatClash is a mihomo/Clash proxy mapping.
	FormatClash NativeFormat = iota
)

// Node is a single proxy server. Raw is the source of truth and is emitted
// as-is (minus compiler-owned keys) to a backend with the same format; View
// is a leniently decoded summary used for analysis only.
type Node struct {
	Name   string
	Format NativeFormat
	Raw    *yaml.Node // flattened mapping, no aliases or merge keys
	View   NodeView
	Pos    diag.Pos
}

// NodeView holds the few fields the compiler needs to reason about a node.
type NodeView struct {
	Type        string
	Server      string
	Port        int
	UDP         *bool  // nil when the node does not say
	DialerProxy string // set when the user already chained this node by hand
}

func (n *Node) UnmarshalYAML(value *yaml.Node) error {
	flat := Flatten(value)
	if flat.Kind != yaml.MappingNode {
		return fmt.Errorf("第 %d 行：节点应该是一个映射（name / type / server / port …）", value.Line)
	}
	n.Format = FormatClash
	n.Raw = flat
	n.Pos = diag.Pos{Line: value.Line, Col: value.Column}
	n.Name = WeakString(Lookup(flat, "name"))
	n.View = viewOf(flat)
	return nil
}

func viewOf(m *yaml.Node) NodeView {
	v := NodeView{
		Type:        WeakString(Lookup(m, "type")),
		Server:      WeakString(Lookup(m, "server")),
		DialerProxy: WeakString(Lookup(m, "dialer-proxy")),
	}
	v.Port, _ = WeakInt(Lookup(m, "port"))
	if b, ok := WeakBool(Lookup(m, "udp")); ok {
		v.UDP = &b
	}
	return v
}

// NewNode builds a node from a Clash proxy mapping that did not come from
// profile.yaml, such as one imported from a subscription.
func NewNode(m *yaml.Node, pos diag.Pos) *Node {
	flat := Flatten(m)
	return &Node{
		Name:   WeakString(Lookup(flat, "name")),
		Format: FormatClash,
		Raw:    flat,
		View:   viewOf(flat),
		Pos:    pos,
	}
}
