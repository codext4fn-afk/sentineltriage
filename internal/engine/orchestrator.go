package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"time"
)

// Options tunes scheduling and resource limits. Zero values select defaults.
type Options struct {
	// Budget is the hard wall-clock limit for the whole run. The engine
	// enforces it rather than hoping collectors are fast.
	Budget time.Duration
	// UnitTimeout caps any single collector. It is clamped to Budget.
	UnitTimeout time.Duration
	// Grace is how long a cancelled collector may take to return before it is
	// abandoned and its partial output sealed.
	Grace time.Duration
	// Concurrency bounds collectors running at once. Collectors manage their
	// own internal worker pools; this only bounds collector-level fan-out.
	Concurrency int
	// MaxFindingsPerCollector caps memory held by a runaway rule.
	MaxFindingsPerCollector int
	// MaxDegradationsPerCollector caps per-collector gap records; an
	// unprivileged /proc sweep can otherwise yield one per foreign PID.
	MaxDegradationsPerCollector int
	// OnFinish, if set, is called once per collector as it completes. It is
	// invoked from engine goroutines and must be safe for concurrent use and
	// return promptly; the UI must never back-pressure the engine.
	OnFinish func(CollectorReport)
	Logger   *slog.Logger
	Now      func() time.Time
}

// Defaults applied by New.
const (
	DefaultBudget                      = 10 * time.Second
	DefaultGrace                       = 250 * time.Millisecond
	DefaultMaxFindingsPerCollector     = 10_000
	DefaultMaxDegradationsPerCollector = 64
)

func (o *Options) withDefaults() (Options, error) {
	out := *o
	if out.Budget == 0 {
		out.Budget = DefaultBudget
	}
	if out.Budget < 0 || out.UnitTimeout < 0 || out.Grace < 0 || out.Concurrency < 0 ||
		out.MaxFindingsPerCollector < 0 || out.MaxDegradationsPerCollector < 0 {
		return out, errors.New("engine options must be non-negative")
	}
	if out.UnitTimeout == 0 || out.UnitTimeout > out.Budget {
		out.UnitTimeout = out.Budget
	}
	if out.Grace == 0 {
		out.Grace = DefaultGrace
	}
	if out.Concurrency == 0 {
		out.Concurrency = runtime.GOMAXPROCS(0)
	}
	if out.MaxFindingsPerCollector == 0 {
		out.MaxFindingsPerCollector = DefaultMaxFindingsPerCollector
	}
	if out.MaxDegradationsPerCollector == 0 {
		out.MaxDegradationsPerCollector = DefaultMaxDegradationsPerCollector
	}
	if out.Logger == nil {
		out.Logger = slog.New(slog.DiscardHandler)
	}
	if out.Now == nil {
		out.Now = time.Now
	}
	return out, nil
}

// Orchestrator runs a fixed set of collectors. It is safe to call Run more
// than once; collectors must then tolerate repeated invocation.
type Orchestrator struct {
	opts       Options
	collectors []Collector
}

// New validates options and collector identities.
func New(opts Options, collectors ...Collector) (*Orchestrator, error) {
	o, err := opts.withDefaults()
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(collectors))
	for _, c := range collectors {
		if c == nil {
			return nil, errors.New("nil collector")
		}
		n := c.Name()
		if n == "" {
			return nil, errors.New("collector with empty name")
		}
		if _, dup := seen[n]; dup {
			return nil, fmt.Errorf("duplicate collector name %q", n)
		}
		seen[n] = struct{}{}
	}
	return &Orchestrator{opts: o, collectors: collectors}, nil
}

// Collectors returns the number of registered collectors.
func (o *Orchestrator) Collectors() int { return len(o.collectors) }

// Run executes every collector and returns once each has finished, timed out,
// or been abandoned. It never returns an error: every failure mode is encoded
// in the per-collector reports so that a partial run still yields a report.
func (o *Orchestrator) Run(ctx context.Context) *Result {
	started := o.opts.Now()
	budgetCtx, cancel := context.WithTimeoutCause(ctx, o.opts.Budget, ErrBudgetExceeded)
	defer cancel()

	batches := make(chan batch)
	result := make(chan *Result, 1)
	go func() { result <- aggregate(batches) }()

	sem := make(chan struct{}, o.opts.Concurrency)
	var wg sync.WaitGroup
	for _, c := range o.collectors {
		// Checked before select: when both cases are ready select picks at
		// random, which would occasionally launch work after the budget ended.
		if budgetCtx.Err() != nil {
			o.deliver(batches, o.notStarted(budgetCtx, c))
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-budgetCtx.Done():
			o.deliver(batches, o.notStarted(budgetCtx, c))
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			o.deliver(batches, o.runUnit(budgetCtx, c))
		}()
	}
	wg.Wait()
	close(batches)

	r := <-result
	r.StartedAt, r.FinishedAt = started, o.opts.Now()
	r.Interrupted = ctx.Err() != nil
	r.BudgetExceeded = !r.Interrupted && errors.Is(context.Cause(budgetCtx), ErrBudgetExceeded)
	return r
}

func (o *Orchestrator) deliver(out chan<- batch, b batch) {
	if o.opts.OnFinish != nil {
		o.opts.OnFinish(b.report)
	}
	out <- b
}
