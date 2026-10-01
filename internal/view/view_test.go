package view

import (
	"slices"
	"testing"

	"nautilus/internal/compile"
	"nautilus/internal/explain"
	"nautilus/internal/route"
)

// Subscriptions repeat rules and carry dozens of app rules; the
// explanation lists each rule once and an exit's app rules in one line.
func TestExplainCondensesSubscriptionRules(t *testing.T) {
	imported := func(m route.Match, value, target string) explain.Hit {
		return explain.Hit{Rule: route.Rule{Match: m, Value: value, Target: target, Origin: route.Origin{Key: "机场", Imported: true}}}
	}
	app := func(value, target string) explain.Hit {
		h := imported(route.MatchProcessName, value, target)
		h.Note = "取决于发起连接的应用"
		return h
	}
	ex := &explain.Explanation{
		Target:   "代理",
		Matched:  ptr(imported(route.MatchDomainKeyword, "youtube", "代理")),
		Shadowed: []explain.Hit{imported(route.MatchDomainKeyword, "youtube", "代理"), imported(route.MatchDomainSuffix, "youtube.com", "代理"), imported(route.MatchDomainSuffix, "youtube.com", "代理")},
		Uncertain: []explain.Hit{app("com.a", "流媒体"), app("com.b", "流媒体"), imported(route.MatchRuleSet, "geoip-cn", "DIRECT"),
			app("com.c", "流媒体"), app("com.d", "DIRECT")},
	}
	v := Explain(&compile.Result{}, ex)
	if want := []string{"订阅 机场 的规则 域名后缀 youtube.com → 代理"}; !slices.Equal(v.Shadowed, want) {
		t.Errorf("shadowed = %q, want %q", v.Shadowed, want)
	}
	want := []string{
		"订阅 机场 的 3 条按应用的规则（com.a、com.b 等）→ 流媒体（取决于发起连接的应用）",
		"订阅 机场 的规则 规则集 geoip-cn → DIRECT（需要运行时判断）",
		"订阅 机场 的规则 进程 com.d → DIRECT（取决于发起连接的应用）",
	}
	if !slices.Equal(v.Uncertain, want) {
		t.Errorf("uncertain =\n%q\nwant\n%q", v.Uncertain, want)
	}
}

func ptr[T any](v T) *T { return &v }
