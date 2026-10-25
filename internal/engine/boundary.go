package engine

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"time"
)

// PanicError is a recovered collector panic.
type PanicError struct {
	Value any
	// Stack is logged at the boundary but never written to reports, which are
	// routinely shared outside the team that ran the scan.
	Stack []byte
}

func (e *PanicError) Error() string { return fmt.Sprintf("collector panicked: %v", e.Value) }

// runUnit executes one collector inside a failure-isolation boundary.
//
// A recover() in main does not catch panics on other goroutines, so every
// collector goroutine carries its own. Cancellation in Go is cooperative: a
// collector stuck in a non-interruptible read (e.g. /proc/<pid>/cmdline of a
// task in D-state) cannot be stopped, only abandoned. After the grace period
// its output is sealed and the goroutine is left to finish or leak; the done
// channel is buffered so the straggler never blocks on send.
func (o *Orchestrator) runUnit(parent context.Context, c Collector) batch {
	start := o.opts.Now()
	ctx, cancel := context.WithTimeoutCause(parent, o.opts.UnitTimeout, ErrUnitTimeout)
	defer cancel()

	sink := newUnitSink(c, o.opts.MaxFindingsPerCollector, o.opts.MaxDegradationsPerCollector)
	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- &PanicError{Value: r, Stack: debug.Stack()}
			}
		}()
		done <- c.Run(ctx, sink)
	}()

	var err error
	abandoned := false
	select {
	case err = <-done:
	case <-ctx.Done():
		grace := time.NewTimer(o.opts.Grace)
		select {
		case err = <-done:
		case <-grace.C:
			abandoned = true
			err = ctx.Err()
		}
		grace.Stop()
	}

	b, rejects := sink.seal()
	b.report.Name, b.report.Engine = c.Name(), c.Engine()
	b.report.Duration = o.opts.Now().Sub(start)
	b.report.DurationMS = b.report.Duration.Milliseconds()
	b.report.Status = classify(ctx, err, len(b.report.Degradations)+b.report.DroppedDegradations > 0)
	if err != nil && b.report.Status != StatusOK && b.report.Status != StatusDegraded {
		b.report.Error = describe(ctx, err)
		if abandoned {
			b.report.Error += errAbandonedSuffix
		}
	}

	log := o.opts.Logger.With("collector", b.report.Name, "status", b.report.Status, "duration_ms", b.report.DurationMS)
	var pe *PanicError
	switch {
	case errors.As(err, &pe):
		log.Error("collector panicked", "panic", fmt.Sprint(pe.Value), "stack", string(pe.Stack))
	case b.report.Status == StatusFailed:
		log.Error("collector failed", "error", b.report.Error)
	case b.report.Status == StatusTimeout:
		log.Warn("collector timed out", "abandoned", abandoned, "partial_findings", b.report.Findings)
	default:
		log.Debug("collector finished", "findings", b.report.Findings, "degradations", len(b.report.Degradations))
	}
	if b.report.RejectedFindings > 0 {
		log.Warn("collector emitted invalid findings", "rejected", b.report.RejectedFindings, "samples", rejects)
	}
	return b
}

// classify maps a collector's return value onto a Status. Context errors are
// attributed via context.Cause: the same DeadlineExceeded can originate from
// the per-collector cap or the global budget, while Canceled means the caller
// (typically SIGINT) stopped the run.
func classify(ctx context.Context, err error, degraded bool) Status {
	var pe *PanicError
	switch {
	case err == nil && degraded:
		return StatusDegraded
	case err == nil:
		return StatusOK
	case errors.As(err, &pe):
		return StatusPanicked
	case errors.Is(err, ErrUnsupported):
		return StatusUnsupported
	case ctx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)):
		if cause := context.Cause(ctx); errors.Is(cause, ErrUnitTimeout) || errors.Is(cause, ErrBudgetExceeded) {
			return StatusTimeout
		}
		return StatusCancelled
	default:
		return StatusFailed
	}
}

func describe(ctx context.Context, err error) string {
	if ctx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		if cause := context.Cause(ctx); cause != nil {
			return cause.Error()
		}
	}
	return err.Error()
}

// notStarted builds the report for a collector that never ran because the
// run ended before a concurrency slot freed up.
func (o *Orchestrator) notStarted(ctx context.Context, c Collector) batch {
	status := StatusCancelled
	if errors.Is(context.Cause(ctx), ErrBudgetExceeded) {
		status = StatusTimeout
	}
	return batch{report: CollectorReport{
		Name:   c.Name(),
		Engine: c.Engine(),
		Status: status,
		Error:  errNotStarted.Error(),
	}}
}
