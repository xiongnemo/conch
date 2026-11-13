package version

import "testing"

func TestString(t *testing.T) {
	const sha = "38e8ec9a1b2c3d4e5f60718293a4b5c6d7e8f900"
	for _, tt := range []struct {
		name  string
		build Build
		want  string
	}{
		{"the tagged commit is the release", Build{Tag: "v0.1.0", Branch: "main", Commit: sha}, "v0.1.0"},
		{"the commits after a tag count up the patch", Build{Tag: "v0.1.0", CommitsSinceTag: 3, Branch: "main", Commit: sha}, "v0.1.3-main-38e8ec9a1b2c"},
		{"from a patch tag too", Build{Tag: "v0.0.1", CommitsSinceTag: 1, Branch: "main", Commit: sha}, "v0.0.2-main-38e8ec9a1b2c"},
		{"dirty is never hidden, even on a tag", Build{Tag: "v0.1.0", Branch: "main", Commit: sha, Dirty: true}, "v0.1.0-main-38e8ec9a1b2c-dirty"},
		{"a build marker is not a base", Build{Tag: "v0.0.5-main-0123456789ab", CommitsSinceTag: 2, Branch: "main", Commit: sha}, "v0.0.3-main-38e8ec9a1b2c"},
		{"no tag: the fallback, never bare", Build{Commit: sha}, "v0.0.1-unknown-38e8ec9a1b2c"},
		{"branch names are made safe", Build{Tag: "v1.2.3", CommitsSinceTag: 1, Branch: "feature/x y", Commit: "abc"}, "v1.2.4-feature-x-y-abc"},
	} {
		if got := tt.build.String(); got != tt.want {
			t.Errorf("%s: %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestIsBase(t *testing.T) {
	for tag, want := range map[string]bool{
		"v0.0.1": true, "v1.20.300": true,
		"v0.0.1-main-0123456789ab": false, "0.0.1": false, "v0.1": false, "v0.1.x": false, "": false,
	} {
		if IsBase(tag) != want {
			t.Errorf("IsBase(%q) = %v", tag, !want)
		}
	}
}
