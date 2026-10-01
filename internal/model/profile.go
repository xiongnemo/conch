// Package model defines the user-facing profile format (profile.yaml).
package model

import (
	"fmt"
	"os"
	"reflect"
	"strings"

	"go.yaml.in/yaml/v3"

	"nautilus/internal/diag"
)

// Profile is what the user writes: where traffic may go (nodes, groups,
// chains) and which traffic goes where (routes).
type Profile struct {
	Nodes    []*Node  `yaml:"nodes"`
	Groups   []*Group `yaml:"groups"`
	Chains   Chains   `yaml:"chains"`
	Routes   Routes   `yaml:"routes"`
	Inbound  Inbound  `yaml:"inbound"`
	DNS      DNS      `yaml:"dns"`
	TUN      TUN      `yaml:"tun"`
	Mode     string   `yaml:"mode"`
	LogLevel string   `yaml:"log-level"`

	File string `yaml:"-"`
}

// Group is an outbound group: several outbounds behind one name.
type Group struct {
	Name      string   `yaml:"name"`
	Type      string   `yaml:"type"`
	Members   []string `yaml:"members"`
	Filter    string   `yaml:"filter"` // regexp over node names, expanded at compile time
	URL       string   `yaml:"url"`
	Interval  int      `yaml:"interval"`
	Tolerance int      `yaml:"tolerance"`
	Lazy      *bool    `yaml:"lazy"`
	Strategy  string   `yaml:"strategy"`

	Pos diag.Pos `yaml:"-"`
}

func (g *Group) UnmarshalYAML(value *yaml.Node) error {
	if err := checkKeys(value, reflect.TypeFor[Group](), "出口组"); err != nil {
		return err
	}
	type plain Group
	if err := value.Decode((*plain)(g)); err != nil {
		return err
	}
	g.Pos = diag.Pos{Line: value.Line, Col: value.Column}
	return nil
}

// Chain is an ordered list of hops: traffic enters Hops[0] first and leaves
// the internet from the last hop.
type Chain struct {
	Name string
	Hops []string
	Pos  diag.Pos
}

// Chains keeps the order chains were written in.
type Chains []*Chain

func (c *Chains) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("第 %d 行：chains 应该写成「链名: [第一跳, 第二跳, …]」", value.Line)
	}
	for i := 0; i+1 < len(value.Content); i += 2 {
		k, v := value.Content[i], value.Content[i+1]
		var hops []string
		if v.Kind != yaml.SequenceNode || v.Decode(&hops) != nil {
			return fmt.Errorf("第 %d 行：链 %q 应该是一个出口名列表，例如 [香港自动, home]", v.Line, k.Value)
		}
		*c = append(*c, &Chain{Name: k.Value, Hops: hops, Pos: diag.Pos{Line: k.Line, Col: k.Column}})
	}
	return nil
}

// Via names where traffic goes: either an outbound name or an inline chain.
type Via struct {
	Name  string
	Chain []string
}

func (v Via) IsZero() bool { return v.Name == "" && v.Chain == nil }

func (v Via) String() string {
	if v.Chain != nil {
		return "[" + strings.Join(v.Chain, " → ") + "]"
	}
	return v.Name
}

func (v *Via) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		v.Name = value.Value
		return nil
	case yaml.SequenceNode:
		return value.Decode(&v.Chain)
	}
	return fmt.Errorf("第 %d 行：出口应该写成一个名字，或 [第一跳, 第二跳, …] 形式的链", value.Line)
}

// Routes is the routing table.
type Routes struct {
	Default    Via        `yaml:"default"`
	Entries    Entries    `yaml:"entries"`
	Lists      []*ListRef `yaml:"lists"`
	ListMirror string     `yaml:"list-mirror"`

	DefaultPos diag.Pos `yaml:"-"`
}

func (r *Routes) UnmarshalYAML(value *yaml.Node) error {
	if err := checkKeys(value, reflect.TypeFor[Routes](), "routes"); err != nil {
		return err
	}
	type plain Routes
	if err := value.Decode((*plain)(r)); err != nil {
		return err
	}
	if i := indexOfKey(value.Content, "default"); i >= 0 {
		r.DefaultPos = diag.Pos{Line: value.Content[i].Line, Col: value.Content[i].Column}
	}
	return nil
}

// Entry is one manual route: a target (domain, IP range, app…) and where
// it goes. Its position in the file does not matter.
type Entry struct {
	Key     string
	Via     Via
	Resolve bool // IP entries: also match domains after resolving them
	Off     bool // only meaningful for the built-in "lan" entry
	Pos     diag.Pos
}

// Entries keeps file order only for stable diagnostics; routing semantics
// never depend on it.
type Entries []*Entry

type entryOptions struct {
	Via     Via  `yaml:"via"`
	Resolve bool `yaml:"resolve"`
}

func (e *Entries) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("第 %d 行：entries 应该写成「目标: 出口」，例如 openai.com: AI-Exit", value.Line)
	}
	for i := 0; i+1 < len(value.Content); i += 2 {
		k, v := value.Content[i], value.Content[i+1]
		ent := &Entry{Key: k.Value, Pos: diag.Pos{Line: k.Line, Col: k.Column}}
		switch v.Kind {
		case yaml.ScalarNode:
			if strings.EqualFold(v.Value, "off") || v.Value == "false" {
				ent.Off = true
			} else {
				ent.Via.Name = v.Value
			}
		case yaml.SequenceNode:
			if err := v.Decode(&ent.Via.Chain); err != nil {
				return fmt.Errorf("第 %d 行：链应该是出口名列表：%w", v.Line, err)
			}
		case yaml.MappingNode:
			if err := checkKeys(v, reflect.TypeFor[entryOptions](), "路由条目"); err != nil {
				return err
			}
			var opts entryOptions
			if err := v.Decode(&opts); err != nil {
				return err
			}
			ent.Via, ent.Resolve = opts.Via, opts.Resolve
		default:
			return fmt.Errorf("第 %d 行：无法识别 %q 的出口", v.Line, k.Value)
		}
		*e = append(*e, ent)
	}
	return nil
}

// ListRef is one entry of the ordered rule-list section.
type ListRef struct {
	List     string   `yaml:"list"`
	Via      Via      `yaml:"via"`
	Behavior string   `yaml:"behavior"` // URL lists: domain | ipcidr | classical
	Format   string   `yaml:"format"`   // URL lists: mrs | yaml | text
	Clash    []string `yaml:"clash"`    // advanced: raw Clash rule lines

	Pos diag.Pos `yaml:"-"`
}

func (l *ListRef) UnmarshalYAML(value *yaml.Node) error {
	if err := checkKeys(value, reflect.TypeFor[ListRef](), "规则列表"); err != nil {
		return err
	}
	type plain ListRef
	if err := value.Decode((*plain)(l)); err != nil {
		return err
	}
	l.Pos = diag.Pos{Line: value.Line, Col: value.Column}
	return nil
}

type Inbound struct {
	MixedPort   int    `yaml:"mixed-port"`
	AllowLAN    bool   `yaml:"allow-lan"`
	BindAddress string `yaml:"bind-address"`
}

func (in *Inbound) UnmarshalYAML(value *yaml.Node) error {
	if err := checkKeys(value, reflect.TypeFor[Inbound](), "inbound"); err != nil {
		return err
	}
	type plain Inbound
	return value.Decode((*plain)(in))
}

type DNS struct {
	Enable      *bool    `yaml:"enable"`
	Mode        string   `yaml:"mode"` // fake-ip | redir-host
	Nameservers []string `yaml:"nameservers"`
	IPv6        bool     `yaml:"ipv6"`
}

func (d *DNS) UnmarshalYAML(value *yaml.Node) error {
	if err := checkKeys(value, reflect.TypeFor[DNS](), "dns"); err != nil {
		return err
	}
	type plain DNS
	return value.Decode((*plain)(d))
}

type TUN struct {
	Enable      bool   `yaml:"enable"`
	Stack       string `yaml:"stack"` // mixed | system | gvisor
	StrictRoute bool   `yaml:"strict-route"`
}

func (t *TUN) UnmarshalYAML(value *yaml.Node) error {
	if err := checkKeys(value, reflect.TypeFor[TUN](), "tun"); err != nil {
		return err
	}
	type plain TUN
	return value.Decode((*plain)(t))
}

// Load reads and parses a profile file.
func Load(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data, path)
}

// Parse parses profile YAML. file is used only for diagnostics.
func Parse(data []byte, file string) (*Profile, error) {
	p := &Profile{File: file}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("%s：%w", file, err)
	}
	if len(root.Content) == 0 {
		return p, nil
	}
	doc := root.Content[0]
	if err := checkKeys(doc, reflect.TypeFor[Profile](), "profile"); err != nil {
		return nil, fmt.Errorf("%s：%w", file, err)
	}
	if err := doc.Decode(p); err != nil {
		return nil, fmt.Errorf("%s：%w", file, err)
	}
	p.setFile(file)
	return p, nil
}

func (p *Profile) setFile(file string) {
	for _, n := range p.Nodes {
		n.Pos.File = file
	}
	for _, g := range p.Groups {
		g.Pos.File = file
	}
	for _, c := range p.Chains {
		c.Pos.File = file
	}
	for _, e := range p.Routes.Entries {
		e.Pos.File = file
	}
	for _, l := range p.Routes.Lists {
		l.Pos.File = file
	}
	p.Routes.DefaultPos.File = file
}
