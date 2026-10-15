package tui

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

type attr uint8

const (
	plain attr = iota
	bold
	reverse
	// picked is the current section or tab on its strip: bold reverse. Thus it
	// is visible, and nobody can mistake it for the cursor row.
	picked
)

type cell struct {
	r rune
	a attr
}

type buffer struct {
	w, h  int
	cells []cell
}

func newBuffer(w, h int) *buffer {
	b := &buffer{w: max(w, 1), h: max(h, 1)}
	b.cells = make([]cell, b.w*b.h)
	for i := range b.cells {
		b.cells[i].r = ' '
	}
	return b
}

// put writes s at (x, y), clipped to the buffer. Tabs and C0 control bytes
// become spaces, so a log line can never move the cursor. C1 controls (an
// 8-bit CSI or OSC), bidi and other format runes become '?', so none of
// them reach the terminal either. put does not touch the box and arrow
// glyphs of the TUI. Text that a device chose is cut down to ASCII where
// the code reads it (admin.Printable).
func (b *buffer) put(x, y int, s string, a attr) {
	if y < 0 || y >= b.h {
		return
	}
	for _, r := range s {
		if x >= b.w {
			return
		}
		if r < 0x20 || r == 0x7f {
			r = ' '
		} else if unsafeRune(r) {
			r = '?'
		}
		if x >= 0 {
			b.cells[y*b.w+x] = cell{r, a}
		}
		x++
	}
}

func unsafeRune(r rune) bool {
	return unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)
}

// line fills row y with s padded to width.
func (b *buffer) line(x, y, width int, s string, a attr) {
	if width <= 0 {
		return
	}
	n := utf8.RuneCountInString(s)
	if n > width {
		s, n = string([]rune(s)[:width]), width
	}
	b.put(x, y, s+strings.Repeat(" ", width-n), a)
}

var attrCodes = map[attr]string{plain: "\x1b[0m", bold: "\x1b[0;1m", reverse: "\x1b[0;7m", picked: "\x1b[0;1;7m"}

// frame renders the full buffer as one write: home, each row, and no
// trailing newline, so the last line never scrolls.
func (b *buffer) frame() []byte {
	var out strings.Builder
	out.WriteString("\x1b[H")
	cur := attr(255)
	for y := 0; y < b.h; y++ {
		if y > 0 {
			out.WriteString("\r\n")
		}
		for x := 0; x < b.w; x++ {
			c := b.cells[y*b.w+x]
			if c.a != cur {
				out.WriteString(attrCodes[c.a])
				cur = c.a
			}
			out.WriteRune(c.r)
		}
	}
	out.WriteString("\x1b[0m")
	return []byte(out.String())
}

func clip(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "~"
}

// col is one table cell: its text and the width of its column, negative
// for right-aligned.
type col struct {
	s string
	w int
}

// cols puts a table row in width w, with two spaces between columns, and
// only whole columns. It leaves off the first column that would not fit,
// and each column after it. It does not cut a column in half. A header and
// its rows declare the same widths, so they drop the same columns.
func cols(w int, cs ...col) string {
	var b strings.Builder
	used := 0
	for i, c := range cs {
		cw, right := c.w, c.w < 0
		if right {
			cw = -cw
		}
		need := cw
		if i > 0 {
			need += 2
		}
		if used+need > w {
			break
		}
		if i > 0 {
			b.WriteString("  ")
		}
		s := clip(c.s, cw)
		pad := strings.Repeat(" ", cw-utf8.RuneCountInString(s))
		if right {
			s = pad + s
		} else {
			s += pad
		}
		b.WriteString(s)
		used += need
	}
	return strings.TrimRight(b.String(), " ")
}
