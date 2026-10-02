package route

import (
	"net/netip"
	"strings"

	"github.com/xiongnemo/conch/internal/diag"
	"github.com/xiongnemo/conch/internal/model"
)

// addImported expands a subscription's own rules. Rules are parsed into
// typed matches where possible so every backend can use them; anything
// else is kept as a raw Clash line, which only Clash-family kernels accept.
// It returns the target of the subscription's MATCH rule, if any.
func (t *Table) addImported(name string, imp *model.ImportedRules, l *model.ListRef, base string, resolve Resolver, d *diag.List) string {
	if !l.Via.IsZero() {
		d.Errorf(l.Pos, "订阅 %q 的规则沿用订阅自己的出口，不能再指定 via", name)
		return ""
	}
	origin := Origin{Tier: TierList, Key: name, Pos: l.Pos, Imported: true}
	var final string
	for _, line := range imp.Lines {
		r, target, ok := t.importedRule(line, imp, base, d, l.Pos)
		if !ok {
			continue
		}
		if r.Match == MatchFinal {
			if final == "" {
				final = target
			}
			continue
		}
		if r.Target, ok = resolve(model.Via{Name: target}, l.Pos); !ok {
			continue
		}
		r.Origin = origin
		t.Rules = append(t.Rules, r)
	}
	return final
}

// importedRule parses one Clash rule line and returns it with its target.
func (t *Table) importedRule(line string, imp *model.ImportedRules, base string, d *diag.List, pos diag.Pos) (Rule, string, bool) {
	fields := strings.Split(line, ",")
	for i := range fields {
		fields[i] = strings.TrimSpace(fields[i])
	}
	typ := strings.ToUpper(fields[0])
	if typ == "MATCH" && len(fields) >= 2 {
		return Rule{Match: MatchFinal}, fields[1], true
	}
	if len(fields) < 3 {
		d.Warnf(pos, "跳过无法识别的订阅规则 %q", line)
		return Rule{}, "", false
	}
	value, target := fields[1], fields[2]
	noResolve := false
	for _, opt := range fields[3:] {
		noResolve = noResolve || opt == "no-resolve"
	}
	r := Rule{Value: value, NoResolve: noResolve}
	switch typ {
	case "DOMAIN":
		r.Match, r.Value = MatchDomain, strings.ToLower(value)
	case "DOMAIN-SUFFIX":
		r.Match, r.Value = MatchDomainSuffix, strings.ToLower(value)
	case "DOMAIN-KEYWORD":
		r.Match, r.Value = MatchDomainKeyword, strings.ToLower(value)
	case "IP-CIDR", "IP-CIDR6":
		p, err := netip.ParsePrefix(value)
		if err != nil {
			d.Warnf(pos, "跳过地址无效的订阅规则 %q", line)
			return Rule{}, "", false
		}
		r.Match, r.Value = MatchIPCIDR, p.Masked().String()
	case "PROCESS-NAME":
		r.Match = MatchProcessName
	case "PROCESS-PATH":
		r.Match = MatchProcessPath
	case "DST-PORT":
		r.Match = MatchDstPort
	case "NETWORK":
		r.Match, r.Value = MatchNetwork, strings.ToLower(value)
	case "GEOSITE", "GEOIP":
		// Served from meta-rules-dat rule sets instead of geodata files,
		// so the kernel needs no geodata download to start.
		cat := strings.ToLower(value)
		if typ == "GEOIP" && cat == "lan" {
			cat = "private"
		}
		p, err := resolveList(&model.ListRef{List: strings.ToLower(typ) + ":" + cat}, base)
		if err != nil {
			d.Warnf(pos, "跳过订阅规则 %q：%v", line, err)
			return Rule{}, "", false
		}
		r.Match, r.Value = MatchRuleSet, t.addProvider(p)
	case "RULE-SET":
		rp := imp.Providers[value]
		if rp == nil {
			d.Warnf(pos, "跳过订阅规则 %q：订阅里没有这个规则集", line)
			return Rule{}, "", false
		}
		p := Provider{Name: rp.Name, Behavior: rp.Behavior, Format: rp.Format, URL: rp.URL, Payload: rp.Payload}
		r.Match, r.Value = MatchRuleSet, t.addProvider(p)
	default:
		idx, err := rawTargetField(fields)
		if err != nil {
			d.Warnf(pos, "跳过订阅规则 %q：%v", line, err)
			return Rule{}, "", false
		}
		return Rule{Match: MatchRaw, Value: line, RawFields: fields, TargetField: idx}, fields[idx], true
	}
	return r, target, true
}
