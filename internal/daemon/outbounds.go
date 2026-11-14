package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/xiongnemo/conch/internal/diag"
	"github.com/xiongnemo/conch/internal/linkparse"
	"github.com/xiongnemo/conch/internal/model"
	"github.com/xiongnemo/conch/internal/proto"
)

// Nodes and chains added from the UIs live in managed.yaml. Each change
// is applied at once; one that would break the config is undone, so a
// typo in the UI never leaves the kernel on an old config.

// changeManaged edits managed.yaml and applies it. If the kernel was
// fine before and the edit breaks the config - it does not compile, or
// the kernel rejects it - the file is put back and the error returned.
func (d *Daemon) changeManaged(ctx context.Context, edit func(*managed) error) error {
	healthy := d.Status().Error == ""
	path := d.managedPath()
	before, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var editErr error
	if err := d.editManaged(func(m *managed) { editErr = edit(m) }); err != nil {
		return err
	}
	if editErr != nil {
		d.restoreManaged(path, before)
		return editErr
	}
	if err = d.Reconcile(ctx); err != nil && healthy {
		d.restoreManaged(path, before)
		d.Reconcile(ctx)
	}
	return err
}

func (d *Daemon) restoreManaged(path string, before []byte) {
	if before == nil {
		os.Remove(path)
	} else {
		os.WriteFile(path, before, 0o600)
	}
	d.mu.Lock()
	d.managedHash = fileHash(path)
	d.mu.Unlock()
}

// definedName returns where profile.yaml defines an outbound name.
func definedName(p *model.Profile, name string) (diag.Pos, bool) {
	if p == nil {
		return diag.Pos{}, false
	}
	for _, n := range p.Nodes {
		if n.Name == name {
			return n.Pos, true
		}
	}
	for _, g := range p.Groups {
		if g.Name == name {
			return g.Pos, true
		}
	}
	for _, c := range p.Chains {
		if c.Name == name {
			return c.Pos, true
		}
	}
	return diag.Pos{}, false
}

func (d *Daemon) loadedProfile() *model.Profile {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.profile
}

// SetChain adds or changes a chain: hops from the entry to the exit.
func (d *Daemon) SetChain(ctx context.Context, name string, hops []string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("链需要一个名字")
	}
	if len(hops) < 2 {
		return errors.New("链至少要有两跳")
	}
	if pos, ok := definedName(d.loadedProfile(), name); ok {
		return &ErrUserFile{What: fmt.Sprintf("出口 %q ", name), Where: pos.String()}
	}
	return d.changeManaged(ctx, func(m *managed) error {
		if managedNode(m, name) != nil || managedGroup(m, name) {
			return fmt.Errorf("已经有叫 %q 的出口了，换一个名字吧", name)
		}
		m.setChain(name, hops)
		return nil
	})
}

// GroupTypes are the kinds of group, as the profile writes them.
var GroupTypes = []string{"select", "url-test", "fallback", "load-balance"}

// SetGroup adds or changes a group of outbounds.
func (d *Daemon) SetGroup(ctx context.Context, name, typ string, members []string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("出口组需要一个名字")
	}
	if !slices.Contains(GroupTypes, typ) {
		return errors.New("出口组的类型应该是 select（手动选择）、url-test（自动最快）、fallback（故障转移）或 load-balance（负载均衡）")
	}
	if len(members) == 0 {
		return errors.New("出口组至少要有一个成员")
	}
	if pos, ok := definedName(d.loadedProfile(), name); ok {
		return &ErrUserFile{What: fmt.Sprintf("出口 %q ", name), Where: pos.String()}
	}
	return d.changeManaged(ctx, func(m *managed) error {
		if managedNode(m, name) != nil || managedChain(m, name) {
			return fmt.Errorf("已经有叫 %q 的出口了，换一个名字吧", name)
		}
		m.setGroup(&model.Group{Name: name, Type: typ, Members: members})
		return nil
	})
}

// DeleteGroup removes a group added from the UIs.
func (d *Daemon) DeleteGroup(ctx context.Context, name string) error {
	if pos, ok := definedName(d.loadedProfile(), name); ok {
		return &ErrUserFile{What: fmt.Sprintf("出口组 %q ", name), Where: pos.String()}
	}
	return d.changeManaged(ctx, func(m *managed) error {
		if !m.removeGroup(name) {
			return fmt.Errorf("出口组 %q %w", name, ErrNotFound)
		}
		return nil
	})
}

// DeleteChain removes a chain added from the UIs.
func (d *Daemon) DeleteChain(ctx context.Context, name string) error {
	if pos, ok := definedName(d.loadedProfile(), name); ok {
		return &ErrUserFile{What: fmt.Sprintf("链 %q ", name), Where: pos.String()}
	}
	return d.changeManaged(ctx, func(m *managed) error {
		if !m.removeChain(name) {
			return fmt.Errorf("链 %q %w", name, ErrNotFound)
		}
		return nil
	})
}

// AddedNodes is what AddNodes did: the names the nodes got, and the
// lines that were not share links it could read, each with why.
type AddedNodes struct {
	Names   []string `json:"names"`
	Skipped []string `json:"skipped,omitempty"`
}

// Summary says it in a line, as the UIs show it.
func (a AddedNodes) Summary() string {
	s := "已添加节点 " + strings.Join(a.Names, "、")
	if len(a.Names) > 3 {
		s = fmt.Sprintf("已添加 %d 个节点：%s 等", len(a.Names), strings.Join(a.Names[:3], "、"))
	}
	if len(a.Skipped) > 0 {
		s += fmt.Sprintf("；%d 条无法识别，已跳过：%s", len(a.Skipped), strings.Join(a.Skipped, "；"))
	}
	return s
}

// AddNodes adds nodes from share links (vmess://, vless://, ss://, …),
// as many as text has: one per line, or separated by spaces, or a
// base64 blob of them as subscriptions send. A name that is taken gets a
// number. All of them are applied at once; lines that cannot be read
// are skipped and reported, and if none can be, nothing changes.
func (d *Daemon) AddNodes(ctx context.Context, text string) (AddedNodes, error) {
	var res AddedNodes
	links := SplitLinks(text)
	if len(links) == 0 {
		return res, fmt.Errorf("没有找到分享链接（应该以 vmess://、vless://、ss://、trojan:// 这样开头）")
	}
	type parsed struct {
		name string
		spec *proto.Spec
	}
	var nodes []parsed
	for _, link := range links {
		name, spec, err := linkparse.Parse(link)
		if err != nil {
			res.Skipped = append(res.Skipped, err.Error())
			continue
		}
		name = strings.TrimSpace(name)
		if name == "" {
			name = spec.Type + " " + spec.Server
		}
		nodes = append(nodes, parsed{name, spec})
	}
	if len(nodes) == 0 {
		if len(res.Skipped) == 1 {
			return res, errors.New(res.Skipped[0])
		}
		return res, fmt.Errorf("没有一条能识别的分享链接：\n%s", strings.Join(res.Skipped, "\n"))
	}
	taken := func(n string) bool {
		_, ok := definedName(d.loadedProfile(), n)
		return ok || d.hasOutbound(n) || slices.Contains(res.Names, n)
	}
	for _, n := range nodes {
		unique := n.name
		for i := 2; taken(unique); i++ {
			unique = fmt.Sprintf("%s (%d)", n.name, i)
		}
		res.Names = append(res.Names, unique)
	}
	err := d.changeManaged(ctx, func(m *managed) error {
		for i, n := range nodes {
			name := res.Names[i]
			if managedNode(m, name) != nil || managedChain(m, name) || managedGroup(m, name) {
				return fmt.Errorf("已经有叫 %q 的出口了", name)
			}
			m.Nodes = append(m.Nodes, model.NewNode(proto.ToClash(name, n.spec), diag.Pos{}))
		}
		return nil
	})
	if err != nil {
		return AddedNodes{}, err
	}
	return res, nil
}

// SplitLinks finds the share links in pasted text. Links are separated by
// line breaks or spaces; a word without "://" continues the link before
// it, since a name after # may have spaces. Text with no "://" at all is
// tried as base64, the way subscriptions send links.
func SplitLinks(text string) []string {
	text = strings.TrimPrefix(strings.TrimSpace(text), "\ufeff")
	if text != "" && !strings.Contains(text, "://") {
		if decoded, err := linkparse.DecodeBase64(strings.Join(strings.Fields(text), "")); err == nil && strings.Contains(string(decoded), "://") {
			text = string(decoded)
		}
	}
	var links []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for i, word := range strings.Fields(line) {
			if i > 0 && !hasScheme(word) && len(links) > 0 {
				links[len(links)-1] += " " + word
				continue
			}
			links = append(links, word)
		}
	}
	return links
}

// hasScheme reports whether s starts like a link: letters, then "://".
func hasScheme(s string) bool {
	i := strings.Index(s, "://")
	if i <= 0 {
		return false
	}
	for j, r := range s[:i] {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || j > 0 && (r >= '0' && r <= '9' || r == '+' || r == '-' || r == '.')) {
			return false
		}
	}
	return true
}

// DeleteNode removes a node added from the UIs.
func (d *Daemon) DeleteNode(ctx context.Context, name string) error {
	if pos, ok := definedName(d.loadedProfile(), name); ok {
		return &ErrUserFile{What: fmt.Sprintf("节点 %q ", name), Where: pos.String()}
	}
	return d.changeManaged(ctx, func(m *managed) error {
		if !m.removeNode(name) {
			return fmt.Errorf("节点 %q %w", name, ErrNotFound)
		}
		return nil
	})
}

func managedNode(m *managed, name string) *model.Node {
	for _, n := range m.Nodes {
		if n.Name == name {
			return n
		}
	}
	return nil
}

func managedGroup(m *managed, name string) bool {
	return slices.ContainsFunc(m.Groups, func(g *model.Group) bool { return g.Name == name })
}

func managedChain(m *managed, name string) bool {
	for _, c := range m.Chains {
		if c.Name == name {
			return true
		}
	}
	return false
}
