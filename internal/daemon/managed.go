package daemon

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/xiongnemo/conch/internal/diag"
	"github.com/xiongnemo/conch/internal/model"
	"github.com/xiongnemo/conch/internal/route"
)

const managedHeader = "# 由 conch 维护：通过 Web UI、TUI、浏览器扩展或 conch 命令添加的节点、链和条目。\n" +
	"# 可以手动修改；写法和 profile.yaml 一样。\n"

// ManagedPath is managed.yaml next to the profile.
func ManagedPath(profile string) string {
	return filepath.Join(filepath.Dir(profile), "managed.yaml")
}

// managed is the daemon-owned file: nodes, chains and route entries added
// from the UIs, kept in the order they were added.
type managed struct {
	Nodes   []*model.Node
	Chains  []*model.Chain
	Entries []managedEntry
}

type managedEntry struct {
	Key, Via string
	Pos      diag.Pos
}

func loadManaged(path string) (*managed, error) {
	m := &managed{}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	p, err := model.Parse(data, path)
	if err != nil {
		return nil, err
	}
	for _, e := range p.Routes.Entries {
		if e.Via.Chain != nil {
			return nil, fmt.Errorf("%s：managed.yaml 里的条目只能指向一个出口名", e.Pos)
		}
		m.Entries = append(m.Entries, managedEntry{e.Key, e.Via.Name, e.Pos})
	}
	m.Nodes, m.Chains = p.Nodes, p.Chains
	return m, nil
}

func (m *managed) save(path string) error {
	doc := &yaml.Node{Kind: yaml.MappingNode}
	if len(m.Nodes) > 0 {
		nodes := &yaml.Node{Kind: yaml.SequenceNode}
		for _, n := range m.Nodes {
			raw := *n.Raw
			raw.Style = yaml.FlowStyle // one node per line
			nodes.Content = append(nodes.Content, &raw)
		}
		doc.Content = append(doc.Content, model.Str("nodes"), nodes)
	}
	if len(m.Chains) > 0 {
		chains := &yaml.Node{Kind: yaml.MappingNode}
		for _, c := range m.Chains {
			hops := &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle}
			for _, h := range c.Hops {
				hops.Content = append(hops.Content, model.Str(h))
			}
			chains.Content = append(chains.Content, model.Str(c.Name), hops)
		}
		doc.Content = append(doc.Content, model.Str("chains"), chains)
	}
	entries := &yaml.Node{Kind: yaml.MappingNode}
	for _, e := range m.Entries {
		entries.Content = append(entries.Content, model.Str(e.Key), model.Str(e.Via))
	}
	doc.Content = append(doc.Content, model.Str("routes"), &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{model.Str("entries"), entries}})
	var buf bytes.Buffer
	buf.WriteString(managedHeader)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	tmp := path + ".part"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// set adds or replaces the entry for key's target, matching targets the
// way the routing table does ("Google.com" and "*.google.com" are one).
func (m *managed) set(key, via string) {
	for i, e := range m.Entries {
		if sameTarget(e.Key, key) {
			m.Entries[i] = managedEntry{Key: key, Via: via}
			return
		}
	}
	m.Entries = append(m.Entries, managedEntry{Key: key, Via: via})
}

func (m *managed) remove(key string) bool {
	for i, e := range m.Entries {
		if sameTarget(e.Key, key) {
			m.Entries = append(m.Entries[:i], m.Entries[i+1:]...)
			return true
		}
	}
	return false
}

// setChain adds or replaces a chain.
func (m *managed) setChain(name string, hops []string) {
	for _, c := range m.Chains {
		if c.Name == name {
			c.Hops = hops
			return
		}
	}
	m.Chains = append(m.Chains, &model.Chain{Name: name, Hops: hops})
}

func (m *managed) removeChain(name string) bool {
	n := len(m.Chains)
	m.Chains = slices.DeleteFunc(m.Chains, func(c *model.Chain) bool { return c.Name == name })
	return len(m.Chains) != n
}

func (m *managed) removeNode(name string) bool {
	n := len(m.Nodes)
	m.Nodes = slices.DeleteFunc(m.Nodes, func(x *model.Node) bool { return x.Name == name })
	return len(m.Nodes) != n
}

func sameTarget(a, b string) bool {
	if strings.EqualFold(a, b) {
		return true
	}
	ta, _, err1 := route.ParseTarget(a)
	tb, _, err2 := route.ParseTarget(b)
	return err1 == nil && err2 == nil && ta.Key() == tb.Key()
}

// definedIn returns where a target is already written in the profile.
func definedIn(p *model.Profile, key string) (diag.Pos, bool) {
	for _, e := range p.Routes.Entries {
		if sameTarget(e.Key, key) {
			return e.Pos, true
		}
	}
	return diag.Pos{}, false
}

// AddManagedRoute writes a permanent route to managed.yaml without a
// running daemon. Targets written in the profile are refused.
func AddManagedRoute(profilePath, key, via string) error {
	if _, _, err := route.ParseTarget(key); err != nil && key != "lan" {
		return err
	}
	p, err := model.Load(profilePath)
	if err != nil {
		return err
	}
	if pos, ok := definedIn(p, key); ok {
		return &ErrUserFile{What: fmt.Sprintf("条目 %q ", key), Where: pos.String()}
	}
	path := ManagedPath(profilePath)
	m, err := loadManaged(path)
	if err != nil {
		return err
	}
	m.set(key, via)
	return m.save(path)
}

// RemoveManagedRoute deletes a route from managed.yaml without a running daemon.
func RemoveManagedRoute(profilePath, key string) error {
	path := ManagedPath(profilePath)
	m, err := loadManaged(path)
	if err != nil {
		return err
	}
	if !m.remove(key) {
		if p, err := model.Load(profilePath); err == nil {
			if pos, ok := definedIn(p, key); ok {
				return &ErrUserFile{What: fmt.Sprintf("条目 %q ", key), Where: pos.String()}
			}
		}
		return fmt.Errorf("managed.yaml 里没有条目 %q", key)
	}
	return m.save(path)
}

// WithManaged adds the routes kept in managed.yaml next to profilePath to
// p, the way the daemon does before compiling.
func WithManaged(p *model.Profile, profilePath string) error {
	path := ManagedPath(profilePath)
	m, err := loadManaged(path)
	if err != nil {
		return err
	}
	mergeEntries(p, m, nil, path)
	return nil
}
