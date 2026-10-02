package main

import (
	"strings"
	"testing"

	"github.com/xiongnemo/conch/internal/diag"
)

// The explanation put above a broken profile is removed before saving,
// also after editors trim trailing spaces, and its line numbers point at
// the lines as the editor shows them.
func TestEditHeader(t *testing.T) {
	profile := "routes:\n  default: x\n"
	header := errorHeader(diag.List{
		{Severity: diag.Error, Pos: diag.Pos{File: "profile.yaml", Line: 2}, Msg: "找不到出口 \"x\""},
		{Severity: diag.Warning, Pos: diag.Pos{Line: 1}, Msg: "只是警告"},
	})
	text := strings.Join(header, "") + profile
	if !strings.Contains(text, "第 6 行：找不到出口") || strings.Contains(text, "只是警告") {
		t.Errorf("header:\n%s", text)
	}
	if lines := strings.Split(text, "\n"); !strings.HasPrefix(lines[5], "  default") {
		t.Errorf("line 6 is %q", lines[5])
	}
	for _, edited := range []string{text, strings.ReplaceAll(text, "#> \n", "#>\n")} {
		if got := string(stripHeader([]byte(edited))); got != profile {
			t.Errorf("stripped to %q", got)
		}
	}
	if got := string(stripHeader([]byte("#> only a header"))); got != "" {
		t.Errorf("a header without a profile stripped to %q", got)
	}
}
