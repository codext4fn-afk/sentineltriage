package engine

import (
	"maps"
	"slices"
	"sync"

	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

// maxRejectSamples bounds how many validation errors are retained per
// collector; a buggy collector can otherwise emit millions.
const maxRejectSamples = 5

// unitSink buffers one collector's output until the boundary seals it.
//
// Buffering per collector, rather than streaming into a shared channel, means
// an abandoned collector goroutine can never send on a closed channel or block
// the aggregator: after seal, emissions are counted and discarded.
type unitSink struct {
	name    string
	engine  finding.Engine
	maxF    int
	maxD    int
	mu      sync.Mutex
	sealed  bool
	out     batch
	samples []string
}

func newUnitSink(c Collector, maxFindings, maxDegradations int) *unitSink {
	return &unitSink{
		name:   c.Name(),
		engine: c.Engine(),
		maxF:   maxFindings,
		maxD:   maxDegradations,
	}
}

// Emit implements Sink. The finding is deep-copied before validation: the
// collector retains its slices and maps and may reuse them, which would
// otherwise race with reporters reading the same backing arrays.
func (s *unitSink) Emit(f finding.Finding) {
	f.Techniques = slices.Clone(f.Techniques)
	f.Evidence = maps.Clone(f.Evidence)
	// Identity is stamped by the engine so one collector cannot attribute
	// findings to another.
	f.Collector, f.Engine = s.name, s.engine
	if f.Fingerprint == "" {
		f.Fingerprint = f.DefaultFingerprint()
	}
	verr := f.Validate()

	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.sealed:
		return
	case verr != nil:
		s.out.report.RejectedFindings++
		if len(s.samples) < maxRejectSamples {
			s.samples = append(s.samples, f.RuleID+": "+verr.Error())
		}
		return
	case len(s.out.findings) >= s.maxF:
		s.out.report.DroppedFindings++
		return
	}
	s.out.findings = append(s.out.findings, f)
}

// Degrade implements Sink.
func (s *unitSink) Degrade(d Degradation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sealed {
		return
	}
	if len(s.out.report.Degradations) >= s.maxD {
		s.out.report.DroppedDegradations++
		return
	}
	s.out.report.Degradations = append(s.out.report.Degradations, d)
}

// seal transfers ownership of the buffered output to the caller. Any later
// Emit or Degrade from a straggling goroutine is discarded.
func (s *unitSink) seal() (batch, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sealed = true
	b, samples := s.out, s.samples
	s.out, s.samples = batch{}, nil
	b.report.Findings = len(b.findings)
	return b, samples
}
