// Package ui renders human-facing output: a zenith-style dashboard printed
// once at the end of a run, and an interactive full-screen variant of the
// same layout. It never writes machine-readable output.
package ui

import (
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/codext4fn-afk/sentineltriage/internal/engine"
	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

// Renderer is implemented by the static and interactive renderers.
type Renderer interface {
	// CollectorDone is called concurrently from engine goroutines.
	CollectorDone(engine.CollectorReport)
	// Summary is called once after reports are written.
	Summary(s RunSummary)
}

// RunSummary is everything the final screen shows.
type RunSummary struct {
	Result   *engine.Result
	FailOn   finding.Severity
	Reports  []string
	ExitCode int
	Reason   string
	Version  string
	Host     string
}

// Plain prints the dashboard once, after the run. While the run is in
// progress it keeps a single status line on a terminal stderr and prints
// nothing on a pipe, so CI logs contain only the final dashboard.
type Plain struct {
	Progress    io.Writer // typically stderr
	ProgressTTY bool      // Progress is an interactive terminal
	Out         io.Writer // typically stdout, or io.Discard for --quiet
	Color       bool
	Width       int

	mu   sync.Mutex
	done int
	line bool
}

// CollectorDone implements Renderer.
func (p *Plain) CollectorDone(r engine.CollectorReport) {
	if !p.ProgressTTY {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.done++
	msg := fmt.Sprintf(" scanning  %d done  last %s %s", p.done, r.Name, r.Status)
	fmt.Fprint(p.Progress, "\r"+padRight(msg, max(p.Width-1, len(msg))))
	p.line = true
}

// Summary implements Renderer.
func (p *Plain) Summary(s RunSummary) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.line {
		fmt.Fprint(p.Progress, "\r"+strings.Repeat(" ", max(p.Width-1, 1))+"\r")
		p.line = false
	}
	width := p.Width
	if width <= 0 {
		width = 120
	}
	v := view{sum: &s, sortCol: colSev}
	for _, l := range v.render(width, 0) {
		fmt.Fprintln(p.Out, l.render(p.Color))
	}
}
