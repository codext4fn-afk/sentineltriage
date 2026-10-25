package ui

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// The layout layer works on styled segments rather than pre-rendered ANSI
// strings. Widths are computed from plain text and escapes are emitted only at
// the final render, so padding and truncation never split an escape sequence
// and the same layout renders identically with color on or off.
//
// NOTE: every rune is treated as one cell. Box-drawing and block elements are
// single-width; East Asian wide characters in file paths would misalign a row,
// which is accepted rather than pulling in a width table.

type sty struct {
	fg, bg string // "#rrggbb" or empty for the terminal default
	bold   bool
}

type seg struct {
	text string
	st   sty
}

type line []seg

func text(s string, st sty) line { return line{{s, st}} }

func (l line) add(s string, st sty) line { return append(l, seg{s, st}) }

func (l line) cat(o line) line { return append(l, o...) }

func (l line) width() int {
	n := 0
	for _, s := range l {
		n += utf8.RuneCountInString(s.text)
	}
	return n
}

// fit truncates or right-pads l to exactly w cells. Truncation ends in an
// ellipsis so a cut value is never mistaken for a complete one.
func (l line) fit(w int) line {
	if w <= 0 {
		return nil
	}
	cur := l.width()
	if cur <= w {
		if cur == w {
			return l
		}
		return append(append(line{}, l...), seg{strings.Repeat(" ", w-cur), sty{}})
	}
	out := make(line, 0, len(l))
	left := w - 1
	for _, s := range l {
		if left == 0 {
			break
		}
		n := utf8.RuneCountInString(s.text)
		if n <= left {
			out = append(out, s)
			left -= n
			continue
		}
		out = append(out, seg{string([]rune(s.text)[:left]), s.st})
		left = 0
	}
	last := sty{}
	if len(out) > 0 {
		last = out[len(out)-1].st
	}
	return append(out, seg{"…", last})
}

// restyle overrides the foreground (and bold) of every segment; used for the
// selected row.
func (l line) restyle(st sty) line {
	out := make(line, len(l))
	for i, s := range l {
		s.st.fg, s.st.bold = st.fg, st.bold
		if st.bg != "" {
			s.st.bg = st.bg
		}
		out[i] = s
	}
	return out
}

func (l line) render(color bool) string {
	var b strings.Builder
	for _, s := range l {
		if !color || s.st == (sty{}) {
			b.WriteString(s.text)
			continue
		}
		b.WriteString(sgr(s.st))
		b.WriteString(s.text)
		b.WriteString("\x1b[0m")
	}
	return b.String()
}

func sgr(st sty) string {
	var codes []string
	if st.bold {
		codes = append(codes, "1")
	}
	if r, g, b, ok := hexRGB(st.fg); ok {
		codes = append(codes, "38;2;"+r+";"+g+";"+b)
	}
	if r, g, b, ok := hexRGB(st.bg); ok {
		codes = append(codes, "48;2;"+r+";"+g+";"+b)
	}
	return "\x1b[" + strings.Join(codes, ";") + "m"
}

func hexRGB(h string) (string, string, string, bool) {
	if len(h) != 7 || h[0] != '#' {
		return "", "", "", false
	}
	v, err := strconv.ParseUint(h[1:], 16, 32)
	if err != nil {
		return "", "", "", false
	}
	return strconv.Itoa(int(v >> 16 & 0xff)), strconv.Itoa(int(v >> 8 & 0xff)), strconv.Itoa(int(v & 0xff)), true
}

// panel is a bordered box with the title set into the top border, as in
// zenith/htop-style dashboards.
type panel struct {
	title  line
	body   []line
	width  int // total, including borders
	height int // total, including borders; 0 sizes to the body
	border string
}

func (p panel) lines() []line {
	inner := p.width - 2
	if inner < 1 {
		return nil
	}
	bs := sty{fg: p.border}
	top := text("┌", bs).cat(p.title.fit(min(p.title.width(), inner)))
	top = top.add(strings.Repeat("─", inner-min(p.title.width(), inner)), bs).add("┐", bs)

	rows := p.height - 2
	if p.height == 0 {
		rows = len(p.body)
	}
	out := make([]line, 0, rows+2)
	out = append(out, top)
	for i := 0; i < rows; i++ {
		var body line
		if i < len(p.body) {
			body = p.body[i]
		}
		out = append(out, text("│", bs).cat(body.fit(inner)).add("│", bs))
	}
	return append(out, text("└"+strings.Repeat("─", inner)+"┘", bs))
}

// hjoin places panels side by side. Shorter panels are padded with blank rows
// so every output row has the combined width.
func hjoin(ps ...panel) []line {
	cols := make([][]line, len(ps))
	h := 0
	for i, p := range ps {
		cols[i] = p.lines()
		h = max(h, len(cols[i]))
	}
	out := make([]line, h)
	for r := 0; r < h; r++ {
		var l line
		for i, c := range cols {
			if r < len(c) {
				l = l.cat(c[r])
			} else {
				l = l.cat(line{}.fit(ps[i].width))
			}
		}
		out[r] = l
	}
	return out
}

// wrap breaks s on spaces into lines of at most w cells.
func wrap(s string, w int) []string {
	if w <= 0 {
		return nil
	}
	var out []string
	var cur strings.Builder
	n := 0
	for _, word := range strings.Fields(s) {
		wl := utf8.RuneCountInString(word)
		if n > 0 && n+1+wl > w {
			out = append(out, cur.String())
			cur.Reset()
			n = 0
		}
		if n > 0 {
			cur.WriteByte(' ')
			n++
		}
		cur.WriteString(word)
		n += wl
	}
	if n > 0 {
		out = append(out, cur.String())
	}
	return out
}

func padLeft(s string, w int) string {
	if n := utf8.RuneCountInString(s); n < w {
		return strings.Repeat(" ", w-n) + s
	}
	return s
}
