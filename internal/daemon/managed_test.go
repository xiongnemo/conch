package daemon

import (
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
	want := map[string]string{"example.com": "C @ 临时，到 15:04", "example.org": "B @ /cfg/managed.yaml"}
	if len(got) != len(want) || got["example.com"] != want["example.com"] || got["example.org"] != want["example.org"] {
		t.Errorf("entries = %v, want %v", got, want)
	}
}
