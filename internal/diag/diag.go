// Package diag carries user-facing diagnostics (errors and warnings) with
// source positions, so every layer can report problems against profile.yaml.
package diag

import (
	"errors"
	"fmt"
	"strings"
)

// Pos is a location in a user-authored file. Zero values are allowed when
// the position is unknown.
type Pos struct {
	File string
	Line int
	Col  int
}

func (p Pos) String() string {
	switch {
	case p.File == "" && p.Line == 0:
		return ""
	case p.Line == 0:
		return p.File
	case p.File == "":
		return fmt.Sprintf("第 %d 行", p.Line)
	default:
		return fmt.Sprintf("%s:%d", p.File, p.Line)
	}
}

type Severity int

const (
	Warning Severity = iota
	Error
)

type Diagnostic struct {
	Severity Severity
	Pos      Pos
	Msg      string
}

func (d Diagnostic) String() string {
	label := "警告"
	if d.Severity == Error {
		label = "错误"
	}
	if pos := d.Pos.String(); pos != "" {
		return fmt.Sprintf("%s %s：%s", label, pos, d.Msg)
	}
	return fmt.Sprintf("%s：%s", label, d.Msg)
}

// List accumulates diagnostics; the zero value is ready to use.
type List []Diagnostic

func (l *List) Errorf(pos Pos, format string, args ...any) {
	*l = append(*l, Diagnostic{Severity: Error, Pos: pos, Msg: fmt.Sprintf(format, args...)})
}

func (l *List) Warnf(pos Pos, format string, args ...any) {
	*l = append(*l, Diagnostic{Severity: Warning, Pos: pos, Msg: fmt.Sprintf(format, args...)})
}

func (l List) HasErrors() bool {
	for _, d := range l {
		if d.Severity == Error {
			return true
		}
	}
	return false
}

// Err folds all error-severity diagnostics into one error, or returns nil.
func (l List) Err() error {
	var msgs []string
	for _, d := range l {
		if d.Severity == Error {
			msgs = append(msgs, d.String())
		}
	}
	if len(msgs) == 0 {
		return nil
	}
	return errors.New(strings.Join(msgs, "\n"))
}
