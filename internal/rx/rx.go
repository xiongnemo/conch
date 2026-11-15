// Package rx is the regular expressions mihomo filters are written in:
// .NET-style (regexp2), with lookahead and backreferences that Go's own
// regexp lacks, so a filter means in conch what it means in mihomo.
// Expressions come from subscriptions: matching is bounded in time.
package rx

import (
	"strings"
	"time"

	"github.com/dlclark/regexp2"
)

// Regexp is one compiled expression.
type Regexp struct{ re *regexp2.Regexp }

// timeout bounds one match: an expression from a subscription must not
// hold conch up, however it backtracks.
const timeout = 200 * time.Millisecond

func Compile(expr string) (*Regexp, error) {
	re, err := regexp2.Compile(expr, regexp2.None)
	if err != nil {
		return nil, err
	}
	re.MatchTimeout = timeout
	return &Regexp{re}, nil
}

// MatchString reports whether s matches; a match that times out does not.
func (r *Regexp) MatchString(s string) bool {
	ok, err := r.re.MatchString(s)
	return ok && err == nil
}

// ReplaceAllString replaces every match; $1 and ${name} are groups.
func (r *Regexp) ReplaceAllString(s, repl string) string {
	out, err := r.re.Replace(s, repl, 0, -1)
	if err != nil {
		return s
	}
	return out
}

// List is several expressions, as mihomo's group filters write them,
// separated by backticks; a name matches if any one does.
type List []*Regexp

func CompileList(expr string) (List, error) {
	var out List
	for part := range strings.SplitSeq(expr, "`") {
		re, err := Compile(part)
		if err != nil {
			return nil, err
		}
		out = append(out, re)
	}
	return out, nil
}

func (l List) MatchString(s string) bool {
	for _, re := range l {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}
