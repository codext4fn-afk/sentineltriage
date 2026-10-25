package ui

import (
	"cmp"
	"fmt"
	"path"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/codext4fn-afk/sentineltriage/internal/attack"
	"github.com/codext4fn-afk/sentineltriage/internal/engine"
	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

type column int

const (
	colSev column = iota
	colRule
	colLoc
	colTech
	colTitle
	numCols
)

var colNames = [numCols]string{"SEV", "RULE", "LOCATION", "ATT&CK", "FINDING"}

// view is the state shared by the static summary and the interactive TUI.
// The static path renders it once with no selection; the TUI mutates it in
// response to keys and re-renders.
type view struct {
	sum         *RunSummary              // nil while the scan is running
	live        []engine.CollectorReport // collector completions seen so far
	sortCol     column
	asc         bool
	minSev      finding.Severity
	selected    int
	offset      int
	interactive bool
}

func (v *view) collectors() []engine.CollectorReport {
	if v.sum != nil {
		return v.sum.Result.Collectors
	}
	return v.live
}

func (v *view) findings() []finding.Finding {
	if v.sum == nil {
		return nil
	}
	return v.sum.Result.Findings
}

// rows returns the filtered, sorted findings shown in the table.
func (v *view) rows() []finding.Finding {
	var out []finding.Finding
	for _, f := range v.findings() {
		if f.Severity >= v.minSev {
			out = append(out, f)
		}
	}
	slices.SortStableFunc(out, func(a, b finding.Finding) int {
		var c int
		switch v.sortCol {
		case colSev:
			c = cmp.Compare(a.Severity, b.Severity)
		case colRule:
			c = cmp.Compare(a.RuleID, b.RuleID)
		case colLoc:
			c = cmp.Compare(locString(a.Location), locString(b.Location))
		case colTech:
			c = cmp.Compare(strings.Join(a.Techniques, ","), strings.Join(b.Techniques, ","))
		case colTitle:
			c = cmp.Compare(a.Title, b.Title)
		}
		if !v.asc {
			c = -c
		}
		if c == 0 {
			return finding.Compare(&a, &b)
		}
		return c
	})
	return out
}

// render lays out the dashboard for a terminal w cells wide. h is the
// terminal height in interactive mode; 0 means size to content.
func (v *view) render(w, h int) []line {
	w = max(w, 60)
	var out []line
	out = append(out, v.topBar(w))

	// Row of summary panels. The ATT&CK panel is dropped on narrow terminals
	// rather than squeezed into an unreadable column.
	const rowH = 8
	sevW := 27
	if w >= 110 {
		rest := w - sevW
		filesW := rest * 55 / 100
		out = append(out, hjoin(v.severityPanel(sevW, rowH), v.filesPanel(filesW, rowH), v.attackPanel(rest-filesW, rowH))...)
	} else {
		out = append(out, hjoin(v.severityPanel(sevW, rowH), v.filesPanel(w-sevW, rowH))...)
	}

	out = append(out, v.collectorsPanel(w).lines()...)

	rows := v.rows()
	detailH := 0
	if v.interactive && h >= 34 && len(rows) > 0 {
		detailH = 9
	}
	tableRows := len(rows)
	if h > 0 {
		// Remaining height after everything else: findings borders (2), its
		// header (1), the footer (1), and the detail panel.
		tableRows = max(3, h-len(out)-4-detailH)
	} else if tableRows > staticRowLimit {
		tableRows = staticRowLimit
	}
	out = append(out, v.findingsPanel(rows, w, tableRows).lines()...)
	if detailH > 0 {
		out = append(out, v.detailPanel(rows[v.selected], w, detailH).lines()...)
	}
	out = append(out, v.footer(w, len(rows)))
	return out
}

// staticRowLimit bounds the non-interactive table; the full set is always in
// the written reports.
const staticRowLimit = 40

func (v *view) topBar(w int) line {
	l := text(" sentinel", sty{fg: cTitle, bold: true})
	if v.sum != nil && v.sum.Version != "" {
		l = l.add(" "+v.sum.Version, stMuted)
	}
	field := func(label string, st sty) {
		l = l.add(" [", stMuted).add(label, st).add("]", stMuted)
	}
	field(runtime.GOOS+"/"+runtime.GOARCH, stTitle)
	if v.sum != nil && v.sum.Host != "" {
		field(v.sum.Host, stTitle)
	}
	if v.sum == nil {
		field(fmt.Sprintf("scanning: %d collectors done", len(v.live)), sty{fg: cYellow})
	} else {
		r := v.sum.Result
		cov := r.Coverage() * 100
		covSt := sty{fg: cOlive}
		if cov < 100 {
			covSt = sty{fg: cYellow}
		}
		field(fmt.Sprintf("%d findings", len(r.Findings)), stTitle)
		field(fmt.Sprintf("coverage %.0f%%", cov), covSt)
		field(fmtDur(r.Duration()), stTitle)
		field("fail-on "+v.sum.FailOn.String(), stTitle)
	}
	if v.interactive {
		help := text("(q)uit ", stMuted)
		gap := w - l.width() - help.width()
		if gap > 0 {
			l = l.add(strings.Repeat(" ", gap), sty{}).cat(help)
		}
	}
	return l.fit(w)
}

var eighths = []rune(" ▁▂▃▄▅▆▇█")

// severityPanel draws one vertical bar per severity, scaled to the largest
// count, in the style of a per-core CPU meter.
func (v *view) severityPanel(w, h int) panel {
	counts := map[finding.Severity]int{}
	total := 0
	for _, f := range v.findings() {
		counts[f.Severity]++
		total++
	}
	peak := 1
	for _, c := range counts {
		peak = max(peak, c)
	}
	const barRows = 4
	body := make([]line, barRows+2)
	sevs := []finding.Severity{finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium, finding.SeverityLow, finding.SeverityInfo}
	for _, s := range sevs {
		units := counts[s] * barRows * 8 / peak
		if counts[s] > 0 && units == 0 {
			units = 1 // a single finding must never render as an empty bar
		}
		for r := 0; r < barRows; r++ {
			level := barRows - 1 - r
			e := min(max(units-level*8, 0), 8)
			body[r] = body[r].add(" ", sty{}).add(strings.Repeat(string(eighths[e]), 3), sevStyle(s)).add(" ", sty{})
		}
		body[barRows] = body[barRows].add(" "+padRight(strconv.Itoa(counts[s]), 4), sevStyle(s))
		body[barRows+1] = body[barRows+1].add(" "+padRight(strings.ToLower(sevShort(s)), 4), stMuted)
	}
	return panel{
		title:  text("Severity", stTitle).add(fmt.Sprintf(" [%d]", total), stMuted),
		body:   body,
		width:  w,
		height: h,
		border: cBorder,
	}
}

// filesPanel lists the locations with the most findings as horizontal bars
// colored by the worst severity at that location.
func (v *view) filesPanel(w, h int) panel {
	type agg struct {
		key   string
		count int
		worst finding.Severity
	}
	byKey := map[string]*agg{}
	for _, f := range v.findings() {
		k := f.Location.Path
		if k == "" {
			k = f.Location.Artifact
		}
		a := byKey[k]
		if a == nil {
			a = &agg{key: k}
			byKey[k] = a
		}
		a.count++
		a.worst = max(a.worst, f.Severity)
	}
	list := make([]*agg, 0, len(byKey))
	for _, a := range byKey {
		list = append(list, a)
	}
	slices.SortFunc(list, func(a, b *agg) int {
		return cmp.Or(cmp.Compare(b.count, a.count), cmp.Compare(b.worst, a.worst), cmp.Compare(a.key, b.key))
	})

	inner := w - 2
	barW := min(24, inner/3)
	nameW := inner - barW - 6
	peak := 1
	if len(list) > 0 {
		peak = list[0].count
	}
	var body []line
	for i, a := range list {
		if i == h-2 {
			break
		}
		units := a.count * barW * 8 / peak
		bar := strings.Repeat("█", units/8)
		if units%8 > 0 {
			bar += string([]rune("▏▎▍▌▋▊▉")[units%8-1])
		}
		body = append(body, text(" "+leftTrunc(a.key, nameW-2), sty{}).fit(nameW).
			add(padRight(bar, barW), sevStyle(a.worst)).
			add(padLeft(strconv.Itoa(a.count), 5), stTitle))
	}
	if len(body) == 0 {
		body = []line{text(" "+v.emptyNote(), stMuted)}
	}
	return panel{
		title:  text("Locations", stTitle).add(fmt.Sprintf(" [%d]", len(list)), stMuted),
		body:   body,
		width:  w,
		height: h,
		border: cBorder,
	}
}

func (v *view) attackPanel(w, h int) panel {
	counts := map[string]int{}
	for _, f := range v.findings() {
		for _, t := range f.Techniques {
			counts[t]++
		}
	}
	ids := make([]string, 0, len(counts))
	for id := range counts {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b string) int { return cmp.Or(cmp.Compare(counts[b], counts[a]), cmp.Compare(a, b)) })

	inner := w - 2
	var body []line
	for i, id := range ids {
		if i == h-2 {
			break
		}
		name := ""
		if t, ok := attack.Lookup(id); ok {
			name = t.Name
			if j := strings.LastIndex(name, ": "); j >= 0 {
				name = name[j+2:]
			}
		}
		l := text(" "+padRight(id, 10), sty{fg: cTeal}).
			cat(text(name, sty{}).fit(max(inner-16, 1))).
			add(padLeft(strconv.Itoa(counts[id]), 5), stTitle)
		body = append(body, l)
	}
	if len(body) == 0 {
		body = []line{text(" "+v.emptyNote(), stMuted)}
	}
	return panel{
		title:  text("ATT&CK", stTitle).add(fmt.Sprintf(" [%d techniques]", len(ids)), stMuted),
		body:   body,
		width:  w,
		height: h,
		border: cBorder,
	}
}

func (v *view) emptyNote() string {
	if v.sum == nil {
		return "scanning..."
	}
	return "no findings"
}

func (v *view) collectorsPanel(w int) panel {
	reports := v.collectors()
	inner := w - 2
	nameW := 26
	for _, r := range reports {
		nameW = max(nameW, utf8.RuneCountInString(r.Name)+2)
	}
	const statusW, timeW, numW, gapW = 12, 9, 10, 6
	noteW := max(inner-nameW-statusW-timeW-numW-gapW, 0)

	header := text(" "+padRight("NAME", nameW-1)+padRight("STATUS", statusW)+padLeft("TIME", timeW-1)+" "+
		padLeft("FINDINGS", numW-1)+" "+padLeft("GAPS", gapW-1)+"  NOTE", stHeader).fit(inner).restyle(stHeader)
	body := []line{header}
	for _, r := range reports {
		gaps := len(r.Degradations) + r.DroppedDegradations
		note := r.Error
		if note == "" && len(r.Degradations) > 0 {
			d := r.Degradations[0]
			note = string(d.Reason) + " " + d.Scope
		}
		body = append(body, text(" "+padRight(r.Name, nameW-1), sty{}).
			add(padRight(string(r.Status), statusW), statusStyle(r.Status)).
			add(padLeft(strconv.FormatInt(r.DurationMS, 10)+"ms", timeW-1)+" ", sty{}).
			add(padLeft(strconv.Itoa(r.Findings), numW-1)+" ", stTitle).
			add(padLeft(strconv.Itoa(gaps), gapW-1), stMuted).
			cat(text("  ", sty{})).
			cat(text(note, stMuted).fit(max(noteW-2, 0))))
	}
	if len(reports) == 0 {
		body = append(body, text(" waiting for collectors...", stMuted))
	}
	return panel{
		title:  text("Collectors", stTitle).add(fmt.Sprintf(" [%d]", len(reports)), stMuted),
		body:   body,
		width:  w,
		border: cBorder,
	}
}

// tableCols computes the findings table column widths for an inner width.
func tableCols(inner int) [numCols]int {
	var c [numCols]int
	c[colSev] = 6
	c[colTech] = 12
	rest := max(inner-c[colSev]-c[colTech]-1, 30)
	c[colRule] = max(rest*30/100, 14)
	c[colLoc] = max(rest*26/100, 14)
	c[colTitle] = max(rest-c[colRule]-c[colLoc], 10)
	return c
}

func (v *view) findingsPanel(rows []finding.Finding, w, visible int) panel {
	inner := w - 2
	cols := tableCols(inner)

	title := text("Findings", stTitle).add(fmt.Sprintf(" [%d]", len(rows)), stMuted)
	if v.minSev > finding.SeverityInfo {
		title = title.add("  filter: >= "+v.minSev.String(), sty{fg: cYellow})
	}
	if v.interactive {
		title = title.add("  Navigate [↑/↓]  Sort Col [,/.]  Asc/Desc [/]  Filter [f] ", stMuted)
	}

	header := text(" ", stHeader)
	for c := column(0); c < numCols; c++ {
		name := colNames[c]
		if c == v.sortCol {
			if v.asc {
				name = "↑" + name
			} else {
				name = "↓" + name
			}
		}
		header = header.add(padRight(name, cols[c]), stHeader)
	}
	body := []line{header.fit(inner).restyle(stHeader)}

	if v.interactive && len(rows) > 0 {
		v.selected = min(max(v.selected, 0), len(rows)-1)
		if v.selected < v.offset {
			v.offset = v.selected
		}
		if v.selected >= v.offset+visible {
			v.offset = v.selected - visible + 1
		}
	} else {
		v.offset = 0
	}

	end := min(v.offset+visible, len(rows))
	for i := v.offset; i < end; i++ {
		f := rows[i]
		tech := strings.Join(f.Techniques, ",")
		l := text(" ", sty{}).
			cat(text(sevShort(f.Severity), sevStyle(f.Severity)).fit(cols[colSev])).
			cat(text(f.RuleID, sty{}).fit(cols[colRule]-1)).add(" ", sty{}).
			cat(text(locString(f.Location), stMuted).fit(cols[colLoc]-1)).add(" ", sty{}).
			cat(text(tech, sty{fg: cTeal}).fit(cols[colTech]-1)).add(" ", sty{}).
			cat(text(f.Title, sty{}).fit(cols[colTitle]))
		if v.interactive && i == v.selected {
			l = l.restyle(stSelect)
		}
		body = append(body, l)
	}
	if len(rows) == 0 {
		body = append(body, text(" "+v.emptyNote(), stMuted))
	} else if !v.interactive && end < len(rows) {
		body = append(body, text(fmt.Sprintf(" ... %d more in the written reports", len(rows)-end), stMuted))
	}

	p := panel{title: title, body: body, width: w, border: cBorder}
	if v.interactive {
		p.height = visible + 3
		p.border = cBorderHi
	}
	return p
}

func (v *view) detailPanel(f finding.Finding, w, h int) panel {
	inner := w - 2
	label := func(s string) line { return text(" "+padRight(s, 8), stMuted) }
	var body []line
	body = append(body, text(" "+sevShort(f.Severity), sevStyle(f.Severity)).
		add("  "+f.RuleID, stBold).
		add(fmt.Sprintf("  confidence %s  risk %.1f", f.Confidence, f.Risk()), stMuted))
	body = append(body, text(" "+f.Title, stTitle))
	body = append(body, label("where").add(locString(f.Location), sty{}))
	if f.Description != "" {
		for i, s := range wrap(f.Description, inner-10) {
			if i == 0 {
				body = append(body, label("why").add(s, sty{}))
			} else {
				body = append(body, label("").add(s, sty{}))
			}
		}
	}
	for i, s := range wrap(f.Remediation, inner-10) {
		if i == 0 {
			body = append(body, label("fix").add(s, sty{}))
		} else {
			body = append(body, label("").add(s, sty{}))
		}
	}
	if len(f.Techniques) > 0 {
		var parts []string
		for _, id := range f.Techniques {
			if t, ok := attack.Lookup(id); ok {
				parts = append(parts, id+" "+t.Name)
			}
		}
		body = append(body, label("att&ck").add(strings.Join(parts, "; "), sty{fg: cTeal}))
	}
	keys := make([]string, 0, len(f.Evidence))
	for k := range f.Evidence {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		body = append(body, label(k).add(f.Evidence[k], stMuted))
	}
	return panel{title: text("Detail", stTitle), body: body, width: w, height: h, border: cBorder}
}

func (v *view) footer(w, shown int) line {
	if v.sum == nil {
		return text(" scanning...", stMuted).fit(w)
	}
	st := sty{fg: cOlive, bold: true}
	if v.sum.ExitCode != 0 {
		st = sty{fg: cRed, bold: true}
	}
	l := text(fmt.Sprintf(" exit %d", v.sum.ExitCode), st).add("  "+v.sum.Reason, sty{})
	if len(v.sum.Reports) > 0 {
		l = l.add("   reports ", stMuted).add(reportList(v.sum.Reports), sty{})
	}
	return l.fit(w)
}

// reportList collapses sentinel-report/sentinel.{json,sarif,html} into one
// brace expression when the reports share a directory and base name.
func reportList(paths []string) string {
	if len(paths) < 2 {
		return strings.Join(paths, " ")
	}
	norm := func(p string) string { return strings.ReplaceAll(p, `\`, "/") }
	dir := path.Dir(norm(paths[0]))
	base := strings.TrimSuffix(path.Base(norm(paths[0])), path.Ext(paths[0]))
	var exts []string
	for _, p := range paths {
		p = norm(p)
		if path.Dir(p) != dir || strings.TrimSuffix(path.Base(p), path.Ext(p)) != base {
			return strings.Join(paths, " ")
		}
		exts = append(exts, strings.TrimPrefix(path.Ext(p), "."))
	}
	return dir + "/" + base + ".{" + strings.Join(exts, ",") + "}"
}

func locString(l finding.Location) string {
	switch {
	case l.Path != "" && l.StartLine > 0:
		return l.Path + ":" + strconv.Itoa(l.StartLine)
	case l.Path != "" && l.Artifact != "":
		return l.Path + " " + l.Artifact
	case l.Path != "":
		return l.Path
	case l.PID > 0:
		return "pid " + strconv.Itoa(l.PID)
	}
	return l.Artifact
}

func leftTrunc(s string, w int) string {
	r := []rune(s)
	if len(r) <= w || w < 2 {
		return s
	}
	return "…" + string(r[len(r)-w+1:])
}

func padRight(s string, w int) string {
	if n := utf8.RuneCountInString(s); n < w {
		return s + strings.Repeat(" ", w-n)
	}
	return s
}

func fmtDur(d time.Duration) string {
	switch {
	case d < time.Millisecond:
		return fmt.Sprintf("%dus", d.Microseconds())
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	default:
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
}
