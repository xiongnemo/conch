package route

import (
	"cmp"
	"slices"
	"strings"

	"github.com/xiongnemo/conch/internal/diag"
	"github.com/xiongnemo/conch/internal/model"
)

// entry is a parsed manual route.
type entry struct {
	target  Target
	via     model.Via
	resolve bool
	key     string // as written; "lan" for all of its expansions
	pos     diag.Pos
	builtin bool // implicit "lan → DIRECT" added by conch
	fromLAN bool // expansion of a lan entry, explicit or implicit
}

// The built-in "lan" entry covers local names and non-routable addresses.
var (
	lanDomains = []string{"localhost", "local", "lan", "home.arpa"}
	lanCIDRs   = []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "255.255.255.255/32",
		"::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
	}
)

func lanEntries(via model.Via, resolve bool, pos diag.Pos, builtin bool) []entry {
	var out []entry
	for _, k := range append(slices.Clone(lanDomains), lanCIDRs...) {
		t, _, _ := ParseTarget(k)
		out = append(out, entry{target: t, via: via, resolve: resolve, key: "lan", pos: pos, builtin: builtin, fromLAN: true})
	}
	return out
}

func parseEntries(es model.Entries, d *diag.List) []entry {
	var out []entry
	sawLAN := false
	for _, e := range es {
		if strings.EqualFold(strings.TrimSpace(e.Key), "lan") {
			sawLAN = true
			switch {
			case e.Off:
			case e.Via.IsZero():
				d.Errorf(e.Pos, "lan 需要指定出口，或写 lan: off 关闭内置的局域网直连")
			default:
				out = append(out, lanEntries(e.Via, e.Resolve, e.Pos, false)...)
			}
			continue
		}
		if e.Off {
			d.Errorf(e.Pos, "%q: off 只能用于内置的 lan 条目", e.Key)
			continue
		}
		if e.Via.IsZero() {
			d.Errorf(e.Pos, "%q 没有指定出口", e.Key)
			continue
		}
		t, note, err := ParseTarget(e.Key)
		if err != nil {
			d.Errorf(e.Pos, "%v", err)
			continue
		}
		if note != "" {
			d.Warnf(e.Pos, "%s", note)
		}
		if e.Resolve && t.Kind != KindIP {
			d.Warnf(e.Pos, "resolve 只对 IP 条目有意义，%q 会忽略它", e.Key)
		}
		out = append(out, entry{target: t, via: e.Via, resolve: e.Resolve, key: e.Key, pos: e.Pos})
	}
	if !sawLAN {
		out = append(out, lanEntries(model.Via{Name: "DIRECT"}, false, diag.Pos{}, true)...)
	}
	return dedupe(out, d)
}

// dedupe rejects two user entries for the same target. An explicit entry
// silently overrides a "lan" expansion, e.g. "10.0.0.0/8: 公司VPN".
func dedupe(es []entry, d *diag.List) []entry {
	seen := map[string]int{}
	var out []entry
	for _, e := range es {
		k := e.target.Key()
		i, dup := seen[k]
		switch {
		case !dup:
			seen[k] = len(out)
			out = append(out, e)
		case out[i].fromLAN && !e.fromLAN:
			out[i] = e
		case !out[i].fromLAN && e.fromLAN:
		default:
			d.Errorf(e.pos, "%q 和 %s 的 %q 是同一个目标，只能保留一个", e.key, out[i].pos, out[i].key)
		}
	}
	return out
}

// sortEntries orders entries by tier, then from most to least specific.
// The order is total, so the input order never affects the output.
func sortEntries(es []entry) {
	slices.SortFunc(es, func(a, b entry) int {
		ta, tb := a.target, b.target
		if c := cmp.Compare(ta.Kind, tb.Kind); c != 0 {
			return c
		}
		switch ta.Kind {
		case KindDomainSuffix:
			if c := cmp.Compare(labels(tb.Value), labels(ta.Value)); c != 0 {
				return c
			}
		case KindKeyword:
			if c := cmp.Compare(len(tb.Value), len(ta.Value)); c != 0 {
				return c
			}
		case KindIP:
			if c := cmp.Compare(tb.Prefix.Bits(), ta.Prefix.Bits()); c != 0 {
				return c
			}
			return ta.Prefix.Addr().Compare(tb.Prefix.Addr())
		}
		return strings.Compare(ta.Value, tb.Value)
	})
}

func entryRule(e entry, target string) Rule {
	r := Rule{
		Value:  e.target.Value,
		Target: target,
		Origin: Origin{Tier: tierOf(e.target.Kind), Key: e.key, Pos: e.pos, Builtin: e.builtin},
	}
	switch e.target.Kind {
	case KindAppPath:
		r.Match = MatchProcessPath
	case KindApp:
		r.Match = MatchProcessName
	case KindDomain:
		r.Match = MatchDomain
	case KindDomainSuffix:
		r.Match = MatchDomainSuffix
	case KindKeyword:
		r.Match = MatchDomainKeyword
	case KindIP:
		r.Match = MatchIPCIDR
		r.NoResolve = !e.resolve
	}
	return r
}
