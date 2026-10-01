package route

import (
	"fmt"
	"strings"

	"nautilus/internal/diag"
	"nautilus/internal/model"
)

// Resolver maps a Via to the name of an emitted outbound. It reports its
// own diagnostics and returns ok=false when the via is unusable.
type Resolver func(v model.Via, pos diag.Pos) (name string, ok bool)

// Table is the compiled routing table.
type Table struct {
	Rules     []Rule
	Providers []Provider
}

// Build compiles the routing table into first-match rules:
// app entries → domain entries → IP entries → rule lists → default.
func Build(r *model.Routes, resolve Resolver, d *diag.List) *Table {
	t := &Table{}
	es := parseEntries(r.Entries, d)
	sortEntries(es)
	for _, e := range es {
		if target, ok := resolve(e.via, e.pos); ok {
			t.Rules = append(t.Rules, entryRule(e, target))
		}
	}

	base, err := listBase(r.ListMirror)
	if err != nil {
		d.Errorf(diag.Pos{}, "%v", err)
		base = defaultListBase
	}
	importedDefault := ""
	for _, l := range r.Lists {
		if imp := r.Imported[l.List]; imp != nil && l.Clash == nil {
			if final := t.addImported(l.List, imp, l, base, resolve, d); importedDefault == "" {
				importedDefault = final
			}
			continue
		}
		t.addList(l, base, resolve, d)
	}

	def, origin := r.Default, Origin{Tier: TierDefault, Key: "default", Pos: r.DefaultPos}
	if def.IsZero() && importedDefault != "" {
		// Without a default of their own, users get the subscription's MATCH.
		def, origin.Imported = model.Via{Name: importedDefault}, true
	}
	if def.IsZero() {
		d.Errorf(r.DefaultPos, "请设置默认出口 routes.default，例如 default: 节点选择")
	} else if target, ok := resolve(def, r.DefaultPos); ok {
		t.Rules = append(t.Rules, Rule{Match: MatchFinal, Target: target, Origin: origin})
	}
	return t
}

func (t *Table) addList(l *model.ListRef, base string, resolve Resolver, d *diag.List) {
	if l.Clash != nil {
		if l.List != "" || !l.Via.IsZero() {
			d.Errorf(l.Pos, "clash 原始规则不能和 list / via 写在同一项里")
			return
		}
		for _, line := range l.Clash {
			t.addRaw(line, l, resolve, d)
		}
		return
	}
	if strings.TrimSpace(l.List) == "" {
		d.Errorf(l.Pos, "规则列表缺少 list，例如 { list: gfwlist, via: 节点选择 }")
		return
	}
	p, err := resolveList(l, base)
	if err != nil {
		d.Errorf(l.Pos, "%v", err)
		return
	}
	if l.Via.IsZero() {
		d.Errorf(l.Pos, "规则列表 %q 需要用 via 指定出口", l.List)
		return
	}
	target, ok := resolve(l.Via, l.Pos)
	if !ok {
		return
	}
	if p.Format == "autoproxy" {
		// "@@" exceptions are excluded from the list: they go direct first.
		ex := p
		ex.Name, ex.Exceptions = p.Name+"-except", true
		ex.Name = t.addProvider(ex)
		t.Rules = append(t.Rules, Rule{Match: MatchRuleSet, Value: ex.Name, Target: "DIRECT", Origin: Origin{Tier: TierList, Key: l.List, Pos: l.Pos}})
	}
	p.Name = t.addProvider(p)
	t.Rules = append(t.Rules, Rule{
		Match:  MatchRuleSet,
		Value:  p.Name,
		Target: target,
		Origin: Origin{Tier: TierList, Key: l.List, Pos: l.Pos},
	})
}

// addProvider registers p, reusing an identical provider and renaming on
// name clashes between different URLs. It returns the provider's name.
func (t *Table) addProvider(p Provider) string {
	name := p.Name
	for n := 2; ; n++ {
		clash := false
		for _, q := range t.Providers {
			if q.Name != name {
				continue
			}
			if q.URL == p.URL && q.Behavior == p.Behavior && q.Format == p.Format && q.Exceptions == p.Exceptions {
				return name
			}
			clash = true
		}
		if !clash {
			p.Name = name
			t.Providers = append(t.Providers, p)
			return name
		}
		name = fmt.Sprintf("%s-%d", p.Name, n)
	}
}

func (t *Table) addRaw(line string, l *model.ListRef, resolve Resolver, d *diag.List) {
	fields := strings.Split(line, ",")
	for i := range fields {
		fields[i] = strings.TrimSpace(fields[i])
	}
	if len(fields) < 2 {
		d.Errorf(l.Pos, "无法识别的 Clash 规则 %q", line)
		return
	}
	idx, err := rawTargetField(fields)
	if err != nil {
		d.Errorf(l.Pos, "%q：%v", line, err)
		return
	}
	target, ok := resolve(model.Via{Name: fields[idx]}, l.Pos)
	if !ok {
		return
	}
	t.Rules = append(t.Rules, Rule{
		Match:       MatchRaw,
		Value:       line,
		Target:      target,
		RawFields:   fields,
		TargetField: idx,
		Origin:      Origin{Tier: TierList, Key: "clash", Pos: l.Pos},
	})
}
