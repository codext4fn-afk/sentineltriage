// Package cli wires flags, configuration, the engine, reporters, and the
// terminal UI into a single testable entry point.
package cli

import (
	"fmt"

	"github.com/codext4fn-afk/sentineltriage/internal/engine"
	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

// ExitCode is the process exit status contract. Values are part of the public
// interface: CI pipelines branch on them, so they never change meaning.
type ExitCode int

const (
	// ExitClean: no findings at or above --fail-on and coverage acceptable.
	ExitClean ExitCode = 0
	// ExitFindings: at least one finding at or above --fail-on.
	ExitFindings ExitCode = 1
	// ExitUsage: invalid flags, config, or rules. Nothing was scanned.
	ExitUsage ExitCode = 2
	// ExitRuntime: no collector observed its scope, or a report could not be
	// written. Distinct from 1 so a broken scanner never masquerades as a
	// failed gate (or, worse, as a clean one).
	ExitRuntime ExitCode = 3
	// ExitCoverage: coverage below --min-coverage. Opt-in.
	ExitCoverage ExitCode = 4
	// ExitInterrupted follows the shell convention 128+SIGINT.
	ExitInterrupted ExitCode = 130
)

// Decide applies the exit-code precedence. Order matters:
//
//  1. Interrupted — the run is incomplete by operator intent.
//  2. Report write failure — consumers would read stale or missing data.
//  3. Findings at threshold — a confirmed finding outranks any coverage
//     concern; even a partial run that found a critical issue must fail
//     the pipeline as "findings", the actionable signal.
//  4. Nothing observed — a scanner that saw nothing must not report clean.
//  5. Coverage below threshold.
func Decide(r *engine.Result, failOn finding.Severity, minCoverage float64, writeErr error) (ExitCode, string) {
	switch {
	case r.Interrupted:
		return ExitInterrupted, "interrupted"
	case writeErr != nil:
		return ExitRuntime, "report write failed: " + writeErr.Error()
	}
	if n := r.CountAtLeast(failOn); n > 0 {
		return ExitFindings, fmt.Sprintf("%d finding(s) at or above %s", n, failOn)
	}
	if !r.Observed() {
		return ExitRuntime, "no collector completed its scope"
	}
	if c := r.Coverage(); c < minCoverage {
		return ExitCoverage, fmt.Sprintf("coverage %.0f%% below required %.0f%%", c*100, minCoverage*100)
	}
	return ExitClean, fmt.Sprintf("no findings at or above %s", failOn)
}
