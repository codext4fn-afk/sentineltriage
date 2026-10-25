package ui

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/codext4fn-afk/sentineltriage/internal/engine"
	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func sample(n int) *RunSummary {
	r := &engine.Result{
		StartedAt:  time.Unix(0, 0),
		FinishedAt: time.Unix(0, int64(3*time.Millisecond)),
		Collectors: []engine.CollectorReport{
			{Name: "audit.files", Status: engine.StatusOK, DurationMS: 2, Findings: n},
			{Name: "host.persistence.windows", Status: engine.StatusDegraded, DurationMS: 18,
				Degradations: []engine.Degradation{{Scope: `C:\Windows\System32\Tasks`, Reason: engine.ReasonPermission}}},
		},
	}
	sevs := []finding.Severity{finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium, finding.SeverityLow}
	for i := range n {
		r.Findings = append(r.Findings, finding.Finding{
			RuleID:      fmt.Sprintf("drift.rule-%02d", i),
			Title:       "a fairly long finding title that will need truncating on narrow terminals",
			Severity:    sevs[i%len(sevs)],
			Techniques:  []string{"T1611"},
			Location:    finding.Location{Path: fmt.Sprintf("deploy/very/deep/path/manifest-%d.yaml", i%3), StartLine: i + 1},
			Remediation: "fix it",
		})
	}
	return &RunSummary{Result: r, FailOn: finding.SeverityHigh, ExitCode: 1, Reason: "findings at or above high",
		Reports: []string{"out/sentinel.json", "out/sentinel.sarif", "out/sentinel.html"}, Version: "v1.0.0", Host: "box"}
}

func plainWidth(s string) int { return utf8.RuneCountInString(ansi.ReplaceAllString(s, "")) }

func TestEveryLineIsExactlyTerminalWidth(t *testing.T) {
	for _, n := range []int{0, 7, 60} {
		for _, w := range []int{80, 100, 140, 220} {
			for _, interactive := range []bool{false, true} {
				v := view{sum: sample(n), interactive: interactive}
				h := 0
				if interactive {
					h = 45
				}
				lines := v.render(w, h)
				for i, l := range lines {
					if got := plainWidth(l.render(true)); got != w {
						t.Fatalf("n=%d w=%d interactive=%v line %d width %d:\n%s", n, w, interactive, i, got, l.render(false))
					}
				}
				if interactive && len(lines) != h {
					t.Errorf("n=%d w=%d: interactive height %d, want %d", n, w, len(lines), h)
				}
			}
		}
	}
}

func TestNoEscapesWithoutColor(t *testing.T) {
	var out bytes.Buffer
	(&Plain{Out: &out, Progress: &out, Width: 120}).Summary(*sample(5))
	if strings.Contains(out.String(), "\x1b[") {
		t.Error("escape sequences emitted with Color=false")
	}
	if !strings.Contains(out.String(), "┌Severity") {
		t.Errorf("dashboard frame missing:\n%s", out.String())
	}
}

func TestColorUsesTruecolor(t *testing.T) {
	var out bytes.Buffer
	(&Plain{Out: &out, Progress: &out, Width: 120, Color: true}).Summary(*sample(3))
	if !strings.Contains(out.String(), "\x1b[38;2;") {
		t.Error("no 24-bit color sequences emitted")
	}
}

func TestStaticTableCapsRows(t *testing.T) {
	var out bytes.Buffer
	(&Plain{Out: &out, Progress: &out, Width: 140}).Summary(*sample(staticRowLimit + 10))
	if !strings.Contains(out.String(), "10 more in the written reports") {
		t.Error("static table not capped")
	}
}

func TestProgressSilentOnPipe(t *testing.T) {
	var prog bytes.Buffer
	p := &Plain{Progress: &prog, Out: &bytes.Buffer{}, Width: 100}
	p.CollectorDone(engine.CollectorReport{Name: "x", Status: engine.StatusOK})
	if prog.Len() != 0 {
		t.Errorf("progress written to a non-terminal: %q", prog.String())
	}
}

func TestSortAndFilter(t *testing.T) {
	v := view{sum: sample(8)}
	if rows := v.rows(); rows[0].Severity != finding.SeverityCritical {
		t.Errorf("default sort not severity-descending: %v", rows[0].Severity)
	}
	v.sortCol, v.asc = colRule, true
	if rows := v.rows(); rows[0].RuleID != "drift.rule-00" || rows[7].RuleID != "drift.rule-07" {
		t.Errorf("rule ascending sort wrong: %s..%s", rows[0].RuleID, rows[7].RuleID)
	}
	v.minSev = finding.SeverityHigh
	for _, f := range v.rows() {
		if f.Severity < finding.SeverityHigh {
			t.Errorf("filter let %v through", f.Severity)
		}
	}
}

func TestTUIKeys(t *testing.T) {
	cancelled := false
	m := &model{v: view{interactive: true}, cancel: func() { cancelled = true }, w: 120, h: 40}
	m.Update(summaryMsg(*sample(10)))
	m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m.Update(tea.KeyMsg{Type: tea.KeyDown})
	if m.v.selected != 2 {
		t.Errorf("selected = %d after two downs", m.v.selected)
	}
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'.'}})
	if m.v.sortCol != colRule {
		t.Errorf("sort column = %d after '.'", m.v.sortCol)
	}
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'f'}})
	if m.v.minSev != finding.SeverityLow || m.v.selected != 0 {
		t.Errorf("filter = %v selected = %d after 'f'", m.v.minSev, m.v.selected)
	}
	if !strings.Contains(m.View(), "Detail") {
		t.Error("detail panel missing at height 40")
	}
	// Quitting after the scan completed must not cancel anything.
	if _, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}}); cmd == nil || cancelled {
		t.Errorf("quit after summary: cmd=%v cancelled=%v", cmd != nil, cancelled)
	}
}

func TestTUIQuitDuringScanCancels(t *testing.T) {
	cancelled := false
	m := &model{v: view{interactive: true}, cancel: func() { cancelled = true }}
	m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if !cancelled {
		t.Error("quitting mid-scan did not cancel the run")
	}
}

func TestReportList(t *testing.T) {
	if got := reportList([]string{`out\sentinel.json`, `out\sentinel.sarif`}); got != "out/sentinel.{json,sarif}" {
		t.Errorf("reportList = %q", got)
	}
	if got := reportList([]string{"a/x.json", "b/y.sarif"}); got != "a/x.json b/y.sarif" {
		t.Errorf("mixed dirs collapsed: %q", got)
	}
}

func TestFitTruncatesWithEllipsis(t *testing.T) {
	l := text("hello", stBold).add("world", sty{}).fit(7)
	if got := l.render(false); got != "hellow…" {
		t.Errorf("fit = %q", got)
	}
	if got := text("ab", sty{}).fit(4).render(false); got != "ab  " {
		t.Errorf("pad = %q", got)
	}
}
