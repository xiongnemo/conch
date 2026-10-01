package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"

	"nautilus/internal/diag"
	"nautilus/internal/model"
	"nautilus/internal/route"
)

const managedHeader = "# 由 nautilus 维护：通过 Web UI、TUI、浏览器扩展或 nautilus route add 添加的条目。\n" +
	"# 可以手动修改；写法和 profile.yaml 的 routes.entries 一样。\n"

// ManagedPath is managed.yaml next to the profile.
func ManagedPath(profile string) string {
	return filepath.Join(filepath.Dir(profile), "managed.yaml")
}

// managed is the daemon-owned file. Only route entries live here for now.
type managed struct {
	Entries [][2]string // key, via; kept in insertion order
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
		m.Entries = append(m.Entries, [2]string{e.Key, e.Via.Name})
	}
	return m, nil
}

func (m *managed) save(path string) error {
	entries := &yaml.Node{Kind: yaml.MappingNode}
	for _, e := range m.Entries {
		entries.Content = append(entries.Content, model.Str(e[0]), model.Str(e[1]))
	}
	doc := &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{
		model.Str("routes"), {Kind: yaml.MappingNode, Content: []*yaml.Node{model.Str("entries"), entries}},
	}}
	data, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	tmp := path + ".part"
	if err := os.WriteFile(tmp, append([]byte(managedHeader), data...), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// set adds or replaces the entry for key's target, matching targets the
// way the routing table does ("Google.com" and "*.google.com" are one).
func (m *managed) set(key, via string) {
	for i, e := range m.Entries {
		if sameTarget(e[0], key) {
			m.Entries[i] = [2]string{key, via}
			return
		}
	}
	m.Entries = append(m.Entries, [2]string{key, via})
}

func (m *managed) remove(key string) bool {
	for i, e := range m.Entries {
		if sameTarget(e[0], key) {
			m.Entries = append(m.Entries[:i], m.Entries[i+1:]...)
			return true
		}
	}
	return false
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
