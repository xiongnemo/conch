// Package version says what a conch binary was built from, in the format
// docs/versioning.md describes:
//
//	v{major}.{minor}.{patch}-{branch}-{commit12}[-dirty]
//
// The patch number is the nearest exact vMAJOR.MINOR.PATCH tag's patch plus
// the commits since that tag, so it advances by itself and is never kept by
// hand. A clean build of exactly a tagged commit renders bare: v0.1.0.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
)

// Set with -ldflags -X by scripts/version.sh. A plain `go build` or `go run`
// has none of them, and Current falls back to what the toolchain stamps in.
var (
	tag             string
	commitsSinceTag string
	branch          string
	commit          string
	dirty           string
)

const (
	fallbackBase = "v0.0.1"
	unknown      = "unknown"
	commitLength = 12
)

// Build is what a version string is made of.
type Build struct {
	Tag             string
	CommitsSinceTag int
	Branch          string
	Commit          string
	Dirty           bool
}

// String renders the version. It is never empty: a version is what a bug
// report quotes, so an unknown part becomes a placeholder, not a gap.
func (b Build) String() string {
	// A clean build of a tagged commit is that release. The v0.0.1 fallback
	// is not a tag anyone made, so it never renders bare.
	if IsBase(b.Tag) && b.CommitsSinceTag == 0 && !b.Dirty {
		return b.Tag
	}
	base := b.Tag
	if !IsBase(base) {
		base = fallbackBase
	}
	v := advancePatch(base, b.CommitsSinceTag) + "-" + cmpOr(sanitizeBranch(b.Branch), unknown) + "-" + cmpOr(shortCommit(b.Commit), unknown)
	if b.Dirty {
		v += "-dirty"
	}
	return v
}

// Current is the build this binary came from.
func Current() Build {
	b := Build{Tag: tag, CommitsSinceTag: atoi(commitsSinceTag), Branch: branch, Commit: commit, Dirty: dirty == "true"}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				if b.Commit == "" {
					b.Commit = s.Value
				}
			case "vcs.modified":
				if dirty == "" {
					b.Dirty = s.Value == "true"
				}
			}
		}
	}
	return b
}

// Describe is the line `conch version` prints.
func Describe() string {
	return fmt.Sprintf("conch %s (%s, %s/%s)", Current(), runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

// IsBase reports whether tag is an exact vMAJOR.MINOR.PATCH tag. Only
// those are bases: a build marker such as v0.0.5-main-0123456789ab carries
// a dash and must never become one, or every build would count from the
// previous build instead of from the last release.
func IsBase(tag string) bool {
	rest, ok := strings.CutPrefix(tag, "v")
	if !ok {
		return false
	}
	parts := strings.Split(rest, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if _, err := strconv.ParseUint(p, 10, 64); err != nil {
			return false
		}
	}
	return true
}

// advancePatch adds the commits since the tag to its patch, so the tagged
// commit is the tag itself and the next one is patch + 1.
func advancePatch(base string, commits int) string {
	parts := strings.Split(strings.TrimPrefix(base, "v"), ".")
	patch, err := strconv.Atoi(parts[2])
	if err != nil || commits < 0 {
		return base
	}
	return fmt.Sprintf("v%s.%s.%d", parts[0], parts[1], patch+commits)
}

// sanitizeBranch replaces what a version or a file name cannot carry.
func sanitizeBranch(name string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '/', '\\', ' ', '\t', ':', '*', '?', '"', '<', '>', '|', '~', '^':
			return '-'
		}
		if r < 0x20 || r == 0x7f {
			return '-'
		}
		return r
	}, name)
}

func shortCommit(full string) string {
	if len(full) <= commitLength {
		return full
	}
	return full[:commitLength]
}

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
