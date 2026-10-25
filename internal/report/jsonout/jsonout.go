// Package jsonout renders the raw telemetry document. It is the canonical,
// lossless export; SARIF and HTML are projections of the same Result.
package jsonout

import (
	"encoding/json"
	"io"
	"runtime"
	"time"

	"github.com/codext4fn-afk/sentineltriage/internal/attack"
	"github.com/codext4fn-afk/sentineltriage/internal/engine"
	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

// SchemaVersion follows semver: additive fields bump minor, removals or type
// changes bump major. Consumers should reject unknown majors.
const SchemaVersion = "1.0.0"

// Document is the top-level JSON telemetry object.
type Document struct {
	SchemaVersion string                   `json:"schema_version"`
	Tool          Tool                     `json:"tool"`
	Run           Run                      `json:"run"`
	Summary       Summary                  `json:"summary"`
	Collectors    []engine.CollectorReport `json:"collectors"`
	Findings      []finding.Finding        `json:"findings"`
}

// Tool identifies the producing build.
type Tool struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	ATTACKVersion string `json:"attack_version"`
}

// Run describes execution context and completeness.
type Run struct {
	StartedAt      time.Time `json:"started_at"`
	FinishedAt     time.Time `json:"finished_at"`
	DurationMS     int64     `json:"duration_ms"`
	Interrupted    bool      `json:"interrupted"`
	BudgetExceeded bool      `json:"budget_exceeded"`
	Coverage       float64   `json:"coverage"`
	OS             string    `json:"os"`
	Arch           string    `json:"arch"`
	Hostname       string    `json:"hostname,omitempty"`
}

// Summary is the pre-computed roll-up most CI consumers read first.
type Summary struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	FailOn     string         `json:"fail_on"`
	// ThresholdBreached mirrors exit code 1 without coupling consumers to
	// process exit semantics.
	ThresholdBreached bool `json:"threshold_breached"`
}

// Meta carries values the engine does not know about.
type Meta struct {
	ToolVersion string
	Hostname    string
	FailOn      finding.Severity
}

// Build projects a Result into a Document. Nil slices are normalized to empty
// arrays so consumers can iterate without null checks.
func Build(r *engine.Result, m Meta) Document {
	by := make(map[string]int, 5)
	for s := finding.SeverityInfo; s <= finding.SeverityCritical; s++ {
		by[s.String()] = 0
	}
	for s, n := range r.SeverityCounts() {
		by[s.String()] = n
	}
	d := Document{
		SchemaVersion: SchemaVersion,
		Tool:          Tool{Name: "sentineltriage", Version: m.ToolVersion, ATTACKVersion: attack.Version},
		Run: Run{
			StartedAt:      r.StartedAt.UTC(),
			FinishedAt:     r.FinishedAt.UTC(),
			DurationMS:     r.Duration().Milliseconds(),
			Interrupted:    r.Interrupted,
			BudgetExceeded: r.BudgetExceeded,
			Coverage:       r.Coverage(),
			OS:             runtime.GOOS,
			Arch:           runtime.GOARCH,
			Hostname:       m.Hostname,
		},
		Summary: Summary{
			Total:             len(r.Findings),
			BySeverity:        by,
			FailOn:            m.FailOn.String(),
			ThresholdBreached: r.CountAtLeast(m.FailOn) > 0,
		},
		Collectors: r.Collectors,
		Findings:   r.Findings,
	}
	if d.Collectors == nil {
		d.Collectors = []engine.CollectorReport{}
	}
	if d.Findings == nil {
		d.Findings = []finding.Finding{}
	}
	return d
}

// Write encodes d as indented JSON. HTML escaping stays enabled: findings
// carry attacker-controlled strings, and this document is routinely pasted
// into web dashboards.
func Write(w io.Writer, d Document) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(d)
}
