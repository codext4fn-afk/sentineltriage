package audit

import (
	"context"
	"runtime"
	"strings"
	"sync"

	"github.com/codext4fn-afk/sentineltriage/internal/audit/drift"
	"github.com/codext4fn-afk/sentineltriage/internal/audit/headers"
	"github.com/codext4fn-afk/sentineltriage/internal/audit/walker"
	"github.com/codext4fn-afk/sentineltriage/internal/engine"
	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

// Collector walks the configured roots and runs every analyzer over each
// selected file. File-level work is parallelized across a worker pool so the
// audit stays within the run's time budget on large trees; the engine's own
// cancellation propagates through ctx into both the walk and the workers.
type Collector struct {
	opts      walker.Options
	analyzers []Analyzer
	workers   int
}

// Config parameterizes the audit collector.
type Config struct {
	Roots        []string
	MaxFileBytes int64
	Exclude      []string
	Workers      int
	Analyzers    []Analyzer
}

// DefaultAnalyzers is the analyzer set compiled into the standard build.
func DefaultAnalyzers() []Analyzer {
	return []Analyzer{drift.Dockerfile{}, drift.Kubernetes{}, headers.Analyzer{}}
}

// New builds an audit collector. With no analyzers supplied it uses
// DefaultAnalyzers.
func New(cfg Config) *Collector {
	a := cfg.Analyzers
	if a == nil {
		a = DefaultAnalyzers()
	}
	w := cfg.Workers
	if w <= 0 {
		w = runtime.GOMAXPROCS(0)
	}
	return &Collector{
		opts: walker.Options{
			Roots:        cfg.Roots,
			MaxFileBytes: cfg.MaxFileBytes,
			Exclude:      cfg.Exclude,
			Select: func(rel string) bool {
				for _, an := range a {
					if an.Applies(rel) {
						return true
					}
				}
				return false
			},
		},
		analyzers: a,
		workers:   w,
	}
}

// Name implements engine.Collector.
func (c *Collector) Name() string { return "audit.files" }

// Engine implements engine.Collector.
func (c *Collector) Engine() finding.Engine { return finding.EngineAudit }

// Run implements engine.Collector.
func (c *Collector) Run(ctx context.Context, sink engine.Sink) error {
	jobs := make(chan walker.File, c.workers)
	var wg sync.WaitGroup
	for range c.workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range jobs {
				c.analyze(f, sink)
			}
		}()
	}

	res, walkErr := walker.Walk(ctx, c.opts, func(f walker.File) error {
		// Honor cancellation at the feed point so a cancelled run does not
		// keep enqueuing work the workers would process after the deadline.
		select {
		case jobs <- f:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	close(jobs)
	wg.Wait()

	if res != nil {
		for _, s := range res.Skipped {
			// Expected exclusions (binary, symlink) are not coverage gaps;
			// only read/permission failures are reported, so absence of
			// findings stays meaningful.
			if isCoverageGap(s.Reason) {
				sink.Degrade(engine.Degradation{
					Scope:  s.Rel,
					Reason: reasonFor(s.Reason),
					Detail: s.Reason,
				})
			}
		}
	}
	return walkErr
}

func (c *Collector) analyze(f walker.File, sink engine.Sink) {
	for _, a := range c.analyzers {
		if a.Applies(f.Rel) {
			a.Analyze(f, sink.Emit)
		}
	}
}

func isCoverageGap(reason string) bool {
	switch {
	case strings.HasPrefix(reason, "binary"), strings.HasPrefix(reason, "symlink"),
		strings.HasPrefix(reason, "not a regular"):
		return false
	default:
		return true
	}
}

func reasonFor(skip string) engine.Reason {
	if strings.Contains(skip, "permission") {
		return engine.ReasonPermission
	}
	return engine.ReasonError
}
