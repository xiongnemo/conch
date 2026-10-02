package xray

import (
	"slices"
	"strings"

	"github.com/xiongnemo/conch/internal/compile"
)

// assignTags maps outbound names to xray tags. Balancer selectors and the
// observatory pick outbounds by tag prefix, so "香港 01" would also select
// "香港 012", and a chain would also select its own hop clones. A name that
// is a prefix of another name therefore gets compile.TagEnd appended; since
// user names never contain TagEnd, the resulting tags are prefix-free while
// most tags stay identical to their names.
func assignTags(names []string) map[string]string {
	sorted := slices.Clone(names)
	slices.Sort(sorted)
	sorted = slices.Compact(sorted)
	tags := make(map[string]string, len(sorted))
	for i, n := range sorted {
		tags[n] = n
		// Names sharing a prefix sort right after it, so checking the
		// next name is enough.
		if i+1 < len(sorted) && strings.HasPrefix(sorted[i+1], n) {
			tags[n] = n + compile.TagEnd
		}
	}
	return tags
}
