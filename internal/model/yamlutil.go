package model

import (
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Flatten returns a deep copy of n with aliases resolved and "<<" merge keys
// applied, so later stages never have to deal with YAML indirection.
// Comments are dropped: the copy is meant for machine output.
func Flatten(n *yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	switch n.Kind {
	case yaml.AliasNode:
		return Flatten(n.Alias)
	case yaml.MappingNode:
		return flattenMapping(n)
	case yaml.DocumentNode, yaml.SequenceNode:
		out := &yaml.Node{Kind: n.Kind, Tag: n.Tag, Style: n.Style, Line: n.Line, Column: n.Column}
		for _, c := range n.Content {
			out.Content = append(out.Content, Flatten(c))
		}
		return out
	default:
		return &yaml.Node{Kind: n.Kind, Tag: n.Tag, Value: n.Value, Style: n.Style, Line: n.Line, Column: n.Column}
	}
}

func flattenMapping(n *yaml.Node) *yaml.Node {
	out := &yaml.Node{Kind: yaml.MappingNode, Tag: n.Tag, Style: n.Style, Line: n.Line, Column: n.Column}
	var merged []*yaml.Node
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Kind == yaml.ScalarNode && k.Tag == "!!merge" {
			src := Flatten(v)
			sources := []*yaml.Node{src}
			if src.Kind == yaml.SequenceNode {
				sources = src.Content
			}
			// Earlier merge sources win over later ones, as in the YAML merge spec.
			for _, s := range sources {
				if s.Kind != yaml.MappingNode {
					continue
				}
				for j := 0; j+1 < len(s.Content); j += 2 {
					if indexOfKey(merged, s.Content[j].Value) < 0 {
						merged = append(merged, s.Content[j], s.Content[j+1])
					}
				}
			}
			continue
		}
		out.Content = append(out.Content, Flatten(k), Flatten(v))
	}
	// Explicit keys override merged ones.
	for j := 0; j+1 < len(merged); j += 2 {
		if indexOfKey(out.Content, merged[j].Value) < 0 {
			out.Content = append(out.Content, merged[j], merged[j+1])
		}
	}
	return out
}

func indexOfKey(pairs []*yaml.Node, key string) int {
	for i := 0; i+1 < len(pairs); i += 2 {
		if pairs[i].Value == key {
			return i
		}
	}
	return -1
}

// NormKey mirrors how mihomo matches proxy option keys: case-insensitive,
// with "_" treated as "-".
func NormKey(k string) string {
	return strings.ToLower(strings.ReplaceAll(k, "_", "-"))
}

// Lookup finds the value for key in mapping m the way mihomo's structure
// decoder does: an exact key wins, otherwise the first normalized match.
func Lookup(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	if i := indexOfKey(m.Content, key); i >= 0 {
		return m.Content[i+1]
	}
	want := NormKey(key)
	for i := 0; i+1 < len(m.Content); i += 2 {
		if NormKey(m.Content[i].Value) == want {
			return m.Content[i+1]
		}
	}
	return nil
}

// DeleteKey removes every spelling variant of key from mapping m.
func DeleteKey(m *yaml.Node, key string) {
	want := NormKey(key)
	kept := m.Content[:0]
	for i := 0; i+1 < len(m.Content); i += 2 {
		if NormKey(m.Content[i].Value) != want {
			kept = append(kept, m.Content[i], m.Content[i+1])
		}
	}
	m.Content = kept
}

// SetKey replaces all spelling variants of key with a single key: value
// pair. An existing exact key keeps its position; otherwise it is appended.
func SetKey(m *yaml.Node, key string, value *yaml.Node) {
	if i := indexOfKey(m.Content, key); i >= 0 {
		m.Content[i+1] = value
		want := NormKey(key)
		kept := m.Content[:0]
		for j := 0; j+1 < len(m.Content); j += 2 {
			if j == i || NormKey(m.Content[j].Value) != want {
				kept = append(kept, m.Content[j], m.Content[j+1])
			}
		}
		m.Content = kept
		return
	}
	DeleteKey(m, key)
	m.Content = append(m.Content, Str(key), value)
}

// Str builds a plain string scalar.
func Str(s string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s}
}

// weakString returns the scalar value of n, or "" for non-scalars.
func weakString(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode || n.Tag == "!!null" {
		return ""
	}
	return n.Value
}

// weakInt accepts ints and numeric strings, like mihomo's weakly typed decoding.
func weakInt(n *yaml.Node) (int, bool) {
	s := strings.TrimSpace(weakString(n))
	if s == "" {
		return 0, false
	}
	v, err := strconv.Atoi(s)
	return v, err == nil
}

// weakBool accepts bools, strconv.ParseBool strings and integers.
func weakBool(n *yaml.Node) (bool, bool) {
	s := strings.TrimSpace(weakString(n))
	if s == "" {
		return false, false
	}
	if b, err := strconv.ParseBool(s); err == nil {
		return b, true
	}
	if v, err := strconv.Atoi(s); err == nil {
		return v != 0, true
	}
	return false, false
}

// checkKeys rejects mapping keys that do not correspond to a yaml tag of the
// struct type t. yaml.v3 does not propagate KnownFields into custom
// unmarshalers, so we validate explicitly to catch typos early. Keys
// starting with "x-" are ignored so users can park YAML anchors there.
func checkKeys(value *yaml.Node, t reflect.Type, what string) error {
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("第 %d 行：%s 应该是一个映射（key: value）", value.Line, what)
	}
	allowed := yamlKeys(t)
	for i := 0; i+1 < len(value.Content); i += 2 {
		k := value.Content[i]
		if !slices.Contains(allowed, k.Value) && !strings.HasPrefix(k.Value, "x-") {
			return fmt.Errorf("第 %d 行：%s 中没有字段 %q（可用字段：%s）", k.Line, what, k.Value, strings.Join(allowed, ", "))
		}
	}
	return nil
}

func yamlKeys(t reflect.Type) []string {
	var keys []string
	for i := range t.NumField() {
		tag := t.Field(i).Tag.Get("yaml")
		name, _, _ := strings.Cut(tag, ",")
		if name != "" && name != "-" {
			keys = append(keys, name)
		}
	}
	return keys
}
