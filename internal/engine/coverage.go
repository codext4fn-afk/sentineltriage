package engine

import (
	"time"

	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

// Status is the terminal state of one collector run.
type Status string

const (
	StatusOK          Status = "ok"
	StatusDegraded    Status = "degraded"
	StatusTimeout     Status = "timeout"
	StatusCancelled   Status = "cancelled"
	StatusFailed      Status = "failed"
	StatusPanicked    Status = "panicked"
	StatusUnsupported Status = "unsupported"
)

// weight is the coverage credit for a status. Partial results from a timeout
// are still reported but earn no credit: the scope they missed is unknown.
func (s Status) weight() float64 {
	switch s {
	case StatusOK:
		return 1.0
	case StatusDegraded:
		return 0.5
	default:
		return 0
	}
}

// Observed reports whether the collector completed its scope, fully or with
// recorded gaps.
func (s Status) Observed() bool { return s == StatusOK || s == StatusDegraded }

// CollectorReport is the per-collector coverage record published in reports.
type CollectorReport struct {
	Name                string         `json:"name"`
	Engine              finding.Engine `json:"engine"`
	Status              Status         `json:"status"`
	Duration            time.Duration  `json:"-"`
	DurationMS          int64          `json:"duration_ms"`
	Findings            int            `json:"findings"`
	Degradations        []Degradation  `json:"degradations,omitempty"`
	DroppedDegradations int            `json:"dropped_degradations,omitempty"`
	DroppedFindings     int            `json:"dropped_findings,omitempty"`
	RejectedFindings    int            `json:"rejected_findings,omitempty"`
	Error               string         `json:"error,omitempty"`
}

// Result is the aggregated, deterministically ordered outcome of a run.
type Result struct {
	StartedAt  time.Time
	FinishedAt time.Time
	// Interrupted is set when the caller's context ended (e.g. SIGINT).
	Interrupted bool
	// BudgetExceeded is set when the global time budget cut the run short.
	BudgetExceeded bool
	Findings       []finding.Finding
	Collectors     []CollectorReport
}

// Duration is the wall-clock time of the run.
func (r *Result) Duration() time.Duration { return r.FinishedAt.Sub(r.StartedAt) }

// Coverage returns the weighted fraction (0–1) of applicable collectors that
// observed their scope. Unsupported collectors are excluded from the
// denominator: a Linux-only collector on Windows is a documented platform gap,
// not a failed run. With no applicable collectors, coverage is 0.
func (r *Result) Coverage() float64 {
	var sum float64
	var n int
	for _, c := range r.Collectors {
		if c.Status == StatusUnsupported {
			continue
		}
		n++
		sum += c.Status.weight()
	}
	if n == 0 {
		return 0
	}
	return sum / float64(n)
}

// Observed reports whether at least one collector completed its scope.
func (r *Result) Observed() bool {
	for _, c := range r.Collectors {
		if c.Status.Observed() {
			return true
		}
	}
	return false
}

// CountAtLeast returns the number of findings at or above min severity.
func (r *Result) CountAtLeast(min finding.Severity) int {
	n := 0
	for i := range r.Findings {
		if r.Findings[i].Severity >= min {
			n++
		}
	}
	return n
}

// SeverityCounts returns the number of findings per severity.
func (r *Result) SeverityCounts() map[finding.Severity]int {
	m := make(map[finding.Severity]int, 5)
	for i := range r.Findings {
		m[r.Findings[i].Severity]++
	}
	return m
}
