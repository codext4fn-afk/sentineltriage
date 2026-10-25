package engine

import (
	"cmp"
	"slices"

	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

// batch is the sealed output of one collector, handed to the aggregator by
// value. After hand-off no other goroutine holds a reference to it.
type batch struct {
	report   CollectorReport
	findings []finding.Finding
}

// aggregate is the sole writer of the Result. Owning the slice in one
// goroutine removes the need for a mutex around the hot append path and makes
// ordering a single, final sort rather than a property of scheduling.
func aggregate(in <-chan batch) *Result {
	r := &Result{}
	for b := range in {
		r.Collectors = append(r.Collectors, b.report)
		r.Findings = append(r.Findings, b.findings...)
	}

	slices.SortFunc(r.Findings, func(a, b finding.Finding) int { return finding.Compare(&a, &b) })
	// Dedup after sorting keeps the highest-ranked instance of each
	// fingerprint, which makes the survivor deterministic.
	seen := make(map[string]struct{}, len(r.Findings))
	r.Findings = slices.DeleteFunc(r.Findings, func(f finding.Finding) bool {
		if _, dup := seen[f.Fingerprint]; dup {
			return true
		}
		seen[f.Fingerprint] = struct{}{}
		return false
	})

	slices.SortFunc(r.Collectors, func(a, b CollectorReport) int { return cmp.Compare(a.Name, b.Name) })
	return r
}
