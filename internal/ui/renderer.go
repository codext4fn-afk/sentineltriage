// Package ui renders human-facing progress and summaries. It never writes
// machine-readable output and never touches stdout unless the caller hands it
// stdout explicitly: report data and UI are separate streams.
package ui

import (
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/codext4fn-afk/sentineltriage/internal/engine"
	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

// Renderer is implemented by the plain renderer and the interactive TUI.
type Renderer interface {
	// CollectorDone is called concurrently from engine goroutines.
	CollectorDone(engine.CollectorReport)
	// Summary is called once after reports are written.
	Summary(s RunSummary)
}

// RunSummary is the information the final screen needs.
type RunSummary struct {
	Result   *engine.Result
	FailOn   finding.Severity
	Reports  []string
	ExitCode int
	Reason   string
}

// maxListed bounds the findings printed to the terminal; the full set is in
// the reports and a wall of text hides the critical items.
const maxListed = 15

// Plain writes line-oriented, optionally colored output suitable for CI logs.
type Plain struct {
	Progress io.Writer // typically stderr
	Out      io.Writer // typically stdout, or io.Discard for --quiet
	Color    bool
	mu       sync.Mutex
}

const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiBlue   = "\x1b[34m"
	ansiMag    = "\x1b[35m"
)

func (p *Plain) paint(code, s string) string {
	if !p.Color {
		return s
	}
	return code + s + ansiReset
}

func (p *Plain) statusColor(s engine.Status) string {
	switch s {
	case engine.StatusOK:
		return ansiGreen
	case engine.StatusDegraded, engine.StatusTimeout, engine.StatusUnsupported:
		return ansiYellow
	default:
		return ansiRed
	}
}

func (p *Plain) severityColor(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical:
		return ansiMag + ansiBold
	case finding.SeverityHigh:
		return ansiRed
	case finding.SeverityMedium:
		return ansiYellow
	case finding.SeverityLow:
		return ansiBlue
	default:
		return ansiDim
	}
}

// CollectorDone implements Renderer.
func (p *Plain) CollectorDone(r engine.CollectorReport) {
	p.mu.Lock()
	defer p.mu.Unlock()
	line := fmt.Sprintf("  %-28s %s %6dms  %d findings", r.Name, p.paint(p.statusColor(r.Status), fmt.Sprintf("%-11s", r.Status)), r.DurationMS, r.Findings)
	if n := len(r.Degradations) + r.DroppedDegradations; n > 0 {
		line += fmt.Sprintf(", %d gaps", n)
	}
	if r.Error != "" {
		line += p.paint(ansiDim, "  ("+r.Error+")")
	}
	fmt.Fprintln(p.Progress, line)
}

// Summary implements Renderer.
func (p *Plain) Summary(s RunSummary) {
	p.mu.Lock()
	defer p.mu.Unlock()
	r, w := s.Result, p.Out
	counts := r.SeverityCounts()

	fmt.Fprintln(w)
	fmt.Fprintln(w, p.paint(ansiBold, "SentinelTriage summary"))
	var parts []string
	for sev := finding.SeverityCritical; ; sev-- {
		parts = append(parts, p.paint(p.severityColor(sev), fmt.Sprintf("%s %d", sev, counts[sev])))
		if sev == finding.SeverityInfo {
			break
		}
	}
	fmt.Fprintf(w, "  findings  %s\n", strings.Join(parts, "  "))
	fmt.Fprintf(w, "  coverage  %.0f%% across %d collectors in %s\n", r.Coverage()*100, len(r.Collectors), r.Duration().Round(1e6))
	if r.Interrupted {
		fmt.Fprintln(w, p.paint(ansiYellow, "  run interrupted: results are partial"))
	} else if r.BudgetExceeded {
		fmt.Fprintln(w, p.paint(ansiYellow, "  time budget exhausted: results are partial"))
	}

	if len(r.Findings) > 0 {
		fmt.Fprintln(w)
		for i := range r.Findings {
			if i == maxListed {
				fmt.Fprintf(w, "  … %d more in the reports\n", len(r.Findings)-maxListed)
				break
			}
			f := &r.Findings[i]
			fmt.Fprintf(w, "  %s %-30s %s%s\n", p.paint(p.severityColor(f.Severity), fmt.Sprintf("%-8s", f.Severity)), f.RuleID, f.Title, p.paint(ansiDim, locationSuffix(f.Location)))
		}
	}
	if len(s.Reports) > 0 {
		fmt.Fprintln(w)
		for _, path := range s.Reports {
			fmt.Fprintf(w, "  report    %s\n", path)
		}
	}
	verdict := fmt.Sprintf("exit %d: %s", s.ExitCode, s.Reason)
	color := ansiGreen
	if s.ExitCode != 0 {
		color = ansiRed
	}
	fmt.Fprintf(w, "\n%s\n", p.paint(color+ansiBold, verdict))
}

func locationSuffix(l finding.Location) string {
	switch {
	case l.Path != "" && l.StartLine > 0:
		return fmt.Sprintf("  %s:%d", l.Path, l.StartLine)
	case l.Path != "":
		return "  " + l.Path
	case l.PID > 0:
		return fmt.Sprintf("  pid %d", l.PID)
	case l.Artifact != "":
		return "  " + l.Artifact
	}
	return ""
}
