// Package audit holds the static analysis engine: a file walker, a set of
// Analyzers, and the collector that drives them under the shared engine
// contract.
//
// Scope note: the analyzers here inspect configuration and infrastructure-as-
// code for insecure settings (configuration drift) and for missing web
// security headers. They deliberately do not harvest credentials from process
// memory or environment; secret scanning is left to dedicated tools run as a
// separate pipeline step.
package audit

import (
	"github.com/codext4fn-afk/sentineltriage/internal/audit/walker"
	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

// Analyzer inspects one file and reports findings. Implementations must be
// safe for concurrent use: the collector runs each Analyzer across many files
// on parallel workers. Analyze must not retain f.Content after returning.
type Analyzer interface {
	Name() string
	// Applies is a cheap pre-filter on path and size so the collector can skip
	// irrelevant files without entering Analyze.
	Applies(f walker.File) bool
	Analyze(f walker.File, emit func(finding.Finding))
}
