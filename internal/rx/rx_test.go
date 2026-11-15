package rx

import (
	"strings"
	"testing"
	"time"
)

func TestMihomoFilters(t *testing.T) {
	// Lookahead, which Go's regexp cannot read: every name without 0.1x.
	re, err := Compile(`^(?!.*0\.1x).*香港`)
	if err != nil {
		t.Fatal(err)
	}
	if !re.MatchString("香港 01") || re.MatchString("香港 02 0.1x") {
		t.Error("lookahead")
	}
	l, err := CompileList("香港`日本")
	if err != nil || !l.MatchString("日本 01") || l.MatchString("美国 01") {
		t.Errorf("backtick list: %v", err)
	}
	if got := mustCompile(t, `^HK-(\d+)$`).ReplaceAllString("HK-01", "香港 $1"); got != "香港 01" {
		t.Errorf("replace = %q", got)
	}
	// A catastrophic expression from a subscription gives up in time.
	start := time.Now()
	mustCompile(t, `^(a+)+$`).MatchString(strings.Repeat("a", 40) + "b")
	if time.Since(start) > 2*time.Second {
		t.Error("matching was not bounded")
	}
}

func mustCompile(t *testing.T, expr string) *Regexp {
	re, err := Compile(expr)
	if err != nil {
		t.Fatal(err)
	}
	return re
}
