package daemon

import (
	"maps"
	"testing"

	"github.com/xiongnemo/conch/internal/compile"
	"github.com/xiongnemo/conch/internal/model"
)

func compiled(t *testing.T, src string) *compile.Result {
	t.Helper()
	p, err := model.Parse([]byte(src), "profile.yaml")
	if err != nil {
		t.Fatal(err)
	}
	res := compile.Compile(p)
	if err := res.Diags.Err(); err != nil {
		t.Fatal(err)
	}
	return res
}

// A provider renaming the selected node keeps it selected under its new
// name; a node that is really gone leaves the choice alone.
func TestSelectionFollowsRenamedNode(t *testing.T) {
	before := compiled(t, `
nodes:
  - { name: 香港 01, type: socks5, server: 192.0.2.1, port: 1080 }
  - { name: 日本 01, type: socks5, server: 192.0.2.2, port: 1080 }
groups:
  - { name: 选择, type: select, members: [香港 01, 日本 01] }
routes: { default: 选择 }
`)
	renamed := compiled(t, `
nodes:
  - { name: 日本 01, type: socks5, server: 192.0.2.2, port: 1080 }
  - { name: "香港 01 [新]", type: socks5, server: 192.0.2.1, port: 1080 }
groups:
  - { name: 选择, type: select, members: [日本 01, "香港 01 [新]"] }
routes: { default: 选择 }
`)
	gone := compiled(t, `
nodes:
  - { name: 日本 01, type: socks5, server: 192.0.2.2, port: 1080 }
  - { name: 香港 02, type: socks5, server: 192.0.2.3, port: 1080 }
groups:
  - { name: 选择, type: select, members: [日本 01, 香港 02] }
routes: { default: 选择 }
`)
	for _, tt := range []struct {
		name   string
		res    *compile.Result
		chosen string
		want   map[string]string
	}{
		{"renamed", renamed, "香港 01", map[string]string{"选择": "香港 01 [新]"}},
		{"still there", renamed, "日本 01", map[string]string{}},
		{"gone", gone, "香港 01", map[string]string{}},
	} {
		got := followRenames(before, tt.res, map[string]string{"选择": tt.chosen})
		if !maps.Equal(got, tt.want) {
			t.Errorf("%s: moved %v, want %v", tt.name, got, tt.want)
		}
	}
	if got := followRenames(nil, renamed, map[string]string{"选择": "香港 01"}); len(got) != 0 {
		t.Errorf("without an earlier result: moved %v", got)
	}
}
