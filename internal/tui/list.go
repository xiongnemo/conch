package tui

import (
	"strings"

	"github.com/charmbracelet/x/ansi"
)

// row is one line of a page. Rows with an item can be selected.
type row struct {
	text string
	item any
}

func title(text string) row { return row{text: titleStyle.Render(text)} }

func blank() row { return row{} }

// list keeps a cursor over the selectable rows of a page and scrolls to it.
type list struct {
	cursor int // among selectable rows
	offset int // first visible row
}

func selectable(rows []row) []int {
	var idx []int
	for i, r := range rows {
		if r.item != nil {
			idx = append(idx, i)
		}
	}
	return idx
}

func (l *list) move(rows []row, delta int) {
	n := len(selectable(rows))
	l.cursor = max(0, min(n-1, l.cursor+delta))
}

func (l *list) home() { l.cursor = 0 }

func (l *list) end(rows []row) { l.cursor = max(0, len(selectable(rows))-1) }

// selected returns the item under the cursor, or nil.
func (l *list) selected(rows []row) any {
	idx := selectable(rows)
	if len(idx) == 0 {
		return nil
	}
	return rows[idx[max(0, min(len(idx)-1, l.cursor))]].item
}

// render draws the rows that fit in h lines of w cells, keeping the
// cursor row in view and highlighted.
func (l *list) render(rows []row, w, h int) string {
	if h <= 0 {
		return ""
	}
	idx := selectable(rows)
	at := -1
	if len(idx) > 0 {
		l.cursor = max(0, min(len(idx)-1, l.cursor))
		at = idx[l.cursor]
	}
	switch {
	case at < 0:
		l.offset = min(l.offset, max(0, len(rows)-h))
	case l.cursor == 0:
		l.offset = 0 // show the headings above the first item
	case at < l.offset:
		l.offset = at
	case at >= l.offset+h:
		l.offset = at - h + 1
	}
	l.offset = max(0, min(l.offset, max(0, len(rows)-h)))
	var b strings.Builder
	for i := l.offset; i < len(rows) && i < l.offset+h; i++ {
		if i > l.offset {
			b.WriteByte('\n')
		}
		if i == at {
			b.WriteString(cursorRow.Render(fit(ansi.Strip(rows[i].text), w)))
		} else {
			b.WriteString(truncate(rows[i].text, w))
		}
	}
	return b.String()
}
