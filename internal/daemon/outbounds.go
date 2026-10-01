package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"nautilus/internal/diag"
	"nautilus/internal/linkparse"
	"nautilus/internal/model"
	"nautilus/internal/proto"
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
		if managedNode(m, name) != nil {
			return fmt.Errorf("已经有叫 %q 的节点了，换一个名字吧", name)
		}
		m.setChain(name, hops)
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

// AddNode adds a node from a share link (vmess://, vless://, ss://, …)
// and returns its name, made unique if the link's name is taken.
func (d *Daemon) AddNode(ctx context.Context, link string) (string, error) {
	name, spec, err := linkparse.Parse(strings.TrimSpace(link))
	if err != nil {
		return "", err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = spec.Type + " " + spec.Server
	}
	taken := func(n string) bool {
		_, ok := definedName(d.loadedProfile(), n)
		return ok || d.hasOutbound(n)
	}
	unique := name
	for i := 2; taken(unique); i++ {
		unique = fmt.Sprintf("%s (%d)", name, i)
	}
	err = d.changeManaged(ctx, func(m *managed) error {
		if managedNode(m, unique) != nil || managedChain(m, unique) {
			return fmt.Errorf("已经有叫 %q 的出口了", unique)
		}
		m.Nodes = append(m.Nodes, model.NewNode(proto.ToClash(unique, spec), diag.Pos{}))
		return nil
	})
	return unique, err
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

func managedChain(m *managed, name string) bool {
	for _, c := range m.Chains {
		if c.Name == name {
			return true
		}
	}
	return false
}
