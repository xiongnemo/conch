package daemon

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"nautilus/internal/model"
)

// Routes from managed.yaml say where they are written; temporary ones
// until when they last, in the words the UIs use.
func TestMergeEntries(t *testing.T) {
	p := &model.Profile{}
	p.Routes.Entries = []*model.Entry{{Key: "example.com", Via: model.Via{Name: "A"}}}
	m := &managed{Entries: []managedEntry{{Key: "example.org", Via: "B"}}}
	until := time.Date(2026, 10, 2, 15, 4, 0, 0, time.Local)
	mergeEntries(p, m, []TempRoute{{Key: "example.com", Via: "C", Expires: until}}, "/cfg/managed.yaml")

	got := map[string]string{}
	for _, e := range p.Routes.Entries {
		got[e.Key] = e.Via.Name + " @ " + e.Pos.String()
	}
	want := map[string]string{"example.com": "C @ 临时条目，到 15:04", "example.org": "B @ /cfg/managed.yaml"}
	if len(got) != len(want) || got["example.com"] != want["example.com"] || got["example.org"] != want["example.org"] {
		t.Errorf("entries = %v, want %v", got, want)
	}
}

// Unix socket paths may not be much longer than 100 bytes on any OS.
func TestSocketDir(t *testing.T) {
	base := filepath.Join(string(filepath.Separator)+"home", "u", "nautilus")
	if got := socketDir(base); got != filepath.Join(base, "run") {
		t.Errorf("socketDir(%s) = %s", base, got)
	}
	deep := filepath.Join(append([]string{base}, slices.Repeat([]string{"deep"}, 20)...)...)
	got := socketDir(deep)
	if len(filepath.Join(got, "xray-probe-4.sock")) > 100 || got != socketDir(deep) || strings.HasPrefix(got, deep) {
		t.Errorf("socketDir(%s) = %s", deep, got)
	}
}
