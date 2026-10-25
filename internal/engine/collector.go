// Package engine schedules collectors under a global time budget, isolates
// their failures, and aggregates their output into a deterministic Result.
//
// The engine trusts nothing a collector does: panics are recovered, deadlines
// are enforced even when a collector ignores its context, and every emitted
// finding is copied and validated before it is admitted.
package engine

import (
	"context"
	"errors"
	"io/fs"
	"os"

	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

// Collector is one independently scheduled unit of host or audit work.
//
// Run must return ctx.Err() (or an error wrapping it) when it stops early due
// to cancellation; returning nil asserts that the collector finished its full
// scope. Implementations may call Sink methods from multiple goroutines.
type Collector interface {
	// Name is a stable dotted identifier, e.g. "host.process". It appears in
	// reports and must be unique within an Orchestrator.
	Name() string
	Engine() finding.Engine
	Run(ctx context.Context, sink Sink) error
}

// Sink receives a collector's output. Implementations are safe for concurrent
// use and never block on downstream consumers.
type Sink interface {
	Emit(f finding.Finding)
	Degrade(d Degradation)
}

// ErrUnsupported is returned (optionally wrapped) by a collector that cannot
// operate on the current platform. It is reported as a coverage gap, not a
// failure.
var ErrUnsupported = errors.New("collector unsupported on this platform")

// Sentinel causes attached to engine-owned contexts so that a deadline can be
// attributed to the per-collector cap or the global budget.
var (
	ErrUnitTimeout     = errors.New("collector exceeded its time limit")
	ErrBudgetExceeded  = errors.New("global time budget exhausted")
	errNotStarted      = errors.New("not started: budget exhausted or run interrupted")
	errAbandonedSuffix = " (collector ignored cancellation and was abandoned)"
)

// Reason classifies why part of a collector's scope went unobserved.
type Reason string

const (
	// ReasonPermission marks EACCES/EPERM, typically non-root or a seccomp/LSM denial.
	ReasonPermission Reason = "permission_denied"
	// ReasonVisibility marks kernel-level hiding the tool did not cause, such
	// as /proc hidepid= or a foreign network namespace.
	ReasonVisibility  Reason = "restricted_visibility"
	ReasonTimeout     Reason = "timeout"
	ReasonUnsupported Reason = "unsupported"
	// ReasonLimit marks deliberate truncation (file size caps, finding caps).
	ReasonLimit Reason = "resource_limit"
	ReasonError Reason = "error"
)

// Degradation records a scope the collector could not fully observe. It is
// the mechanism by which low-privilege runs stay honest: absence of findings
// is only meaningful alongside the list of places that were not examined.
type Degradation struct {
	Scope  string `json:"scope"`
	Reason Reason `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

// DegradationFor converts an I/O error on scope into a Degradation. It returns
// ok=false for fs.ErrNotExist, which during live triage almost always means a
// process exited or a file was rotated mid-read: a race, not a coverage gap.
func DegradationFor(scope string, err error) (d Degradation, ok bool) {
	switch {
	case err == nil, errors.Is(err, fs.ErrNotExist):
		return Degradation{}, false
	case errors.Is(err, fs.ErrPermission), errors.Is(err, os.ErrPermission):
		return Degradation{Scope: scope, Reason: ReasonPermission, Detail: err.Error()}, true
	case errors.Is(err, context.DeadlineExceeded):
		return Degradation{Scope: scope, Reason: ReasonTimeout, Detail: err.Error()}, true
	default:
		return Degradation{Scope: scope, Reason: ReasonError, Detail: err.Error()}, true
	}
}
