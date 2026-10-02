package route

import "github.com/xiongnemo/conch/internal/diag"

// Tier is a section of the routing table. Tiers are always evaluated in
// this order; only rule lists are ordered by the user.
type Tier int

const (
	TierApp Tier = iota
	TierDomain
	TierIP
	TierList
	TierDefault
)

func (t Tier) String() string {
	return [...]string{"app", "domain", "ip", "list", "default"}[t]
}

func tierOf(k Kind) Tier {
	switch k {
	case KindApp, KindAppPath:
		return TierApp
	case KindIP:
		return TierIP
	default:
		return TierDomain
	}
}

// Match is what a compiled rule tests.
type Match int

const (
	MatchProcessPath Match = iota
	MatchProcessName
	MatchDomain
	MatchDomainSuffix
	MatchDomainKeyword
	MatchIPCIDR
	MatchRuleSet // Value is a Provider name
	MatchDstPort // Value is a port or range, e.g. 443 or 1000-2000
	MatchNetwork // Value is tcp or udp
	MatchRaw     // Value is a raw Clash rule line; RawFields/TargetField locate its target
	MatchFinal
)

// Rule is one backend-neutral routing rule; rules are evaluated first-match.
type Rule struct {
	Match     Match
	Value     string
	NoResolve bool
	Target    string // emitted outbound name
	Origin    Origin

	// For MatchRaw: the line's fields, with the target at TargetField.
	RawFields   []string
	TargetField int
}

// Origin links a compiled rule back to what the user wrote.
type Origin struct {
	Tier     Tier
	Key      string // entry key, list name, or "default"
	Pos      diag.Pos
	Builtin  bool // added by conch (e.g. the default "lan" entry)
	Imported bool // came with a subscription rather than written by the user
}
