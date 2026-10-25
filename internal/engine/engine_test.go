package engine

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

type fakeCollector struct {
	name string
	run  func(ctx context.Context, s Sink) error
}

func (f *fakeCollector) Name() string                          { return f.name }
func (f *fakeCollector) Engine() finding.Engine                { return finding.EngineHost }
func (f *fakeCollector) Run(ctx context.Context, s Sink) error { return f.run(ctx, s) }

func fake(name string, run func(context.Context, Sink) error) Collector {
	return &fakeCollector{name: name, run: run}
}

func mkFinding(rule string, sev finding.Severity) finding.Finding {
	return finding.Finding{RuleID: rule, Title: rule, Severity: sev, Location: finding.Location{Path: rule}}
}

func mustRun(t *testing.T, ctx context.Context, opts Options, cs ...Collector) *Result {
	t.Helper()
	o, err := New(opts, cs...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return o.Run(ctx)
}

func report(t *testing.T, r *Result, name string) CollectorReport {
	t.Helper()
	for _, c := range r.Collectors {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no report for collector %q", name)
	return CollectorReport{}
}

func TestPanicIsIsolated(t *testing.T) {
	r := mustRun(t, context.Background(), Options{},
		fake("boom", func(context.Context, Sink) error { panic("nil map write") }),
		fake("nilpanic", func(context.Context, Sink) error { panic(nil) }),
		fake("healthy", func(_ context.Context, s Sink) error {
			s.Emit(mkFinding("healthy.rule", finding.SeverityHigh))
			return nil
		}),
	)
	if got := report(t, r, "boom"); got.Status != StatusPanicked || !strings.Contains(got.Error, "nil map write") {
		t.Errorf("boom: status=%s error=%q", got.Status, got.Error)
	}
	if got := report(t, r, "nilpanic"); got.Status != StatusPanicked {
		t.Errorf("panic(nil) not caught: status=%s", got.Status)
	}
	if got := report(t, r, "healthy"); got.Status != StatusOK || got.Findings != 1 {
		t.Errorf("sibling affected by panic: %+v", got)
	}
	if len(r.Findings) != 1 {
		t.Errorf("findings = %d, want 1", len(r.Findings))
	}
}

func TestCooperativeTimeoutKeepsPartialFindings(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := mustRun(t, context.Background(), Options{Budget: 10 * time.Second, UnitTimeout: time.Second},
			fake("slow", func(ctx context.Context, s Sink) error {
				s.Emit(mkFinding("partial", finding.SeverityMedium))
				<-ctx.Done()
				return ctx.Err()
			}),
		)
		got := report(t, r, "slow")
		if got.Status != StatusTimeout || got.Findings != 1 {
			t.Errorf("status=%s findings=%d, want timeout/1", got.Status, got.Findings)
		}
		if !strings.Contains(got.Error, ErrUnitTimeout.Error()) {
			t.Errorf("timeout not attributed to unit cap: %q", got.Error)
		}
		if r.BudgetExceeded {
			t.Error("unit timeout misreported as budget exhaustion")
		}
	})
}

func TestUncooperativeCollectorIsAbandoned(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		r := mustRun(t, context.Background(), Options{UnitTimeout: time.Second, Grace: 250 * time.Millisecond},
			fake("stuck", func(_ context.Context, s Sink) error {
				s.Emit(mkFinding("before", finding.SeverityLow))
				// Simulates an uninterruptible read; ignores ctx entirely.
				time.Sleep(time.Hour)
				s.Emit(mkFinding("after-seal", finding.SeverityCritical))
				s.Degrade(Degradation{Scope: "late", Reason: ReasonError})
				return nil
			}),
		)
		if elapsed := time.Since(start); elapsed != 1250*time.Millisecond {
			t.Errorf("Run returned after %v, want unit timeout + grace (1.25s)", elapsed)
		}
		got := report(t, r, "stuck")
		if got.Status != StatusTimeout || !strings.Contains(got.Error, "abandoned") {
			t.Errorf("status=%s error=%q", got.Status, got.Error)
		}
		if len(r.Findings) != 1 || r.Findings[0].RuleID != "before" {
			t.Errorf("findings = %+v, want only pre-seal finding", r.Findings)
		}
		// synctest.Test waits for the straggler; its post-seal emissions must
		// not mutate the already-returned Result.
		time.Sleep(2 * time.Hour)
		synctest.Wait()
		if len(r.Findings) != 1 || len(r.Collectors[0].Degradations) != 0 {
			t.Error("straggler mutated sealed result")
		}
	})
}

func TestBudgetExhaustionMarksUnstartedCollectors(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		block := func(ctx context.Context, _ Sink) error { <-ctx.Done(); return ctx.Err() }
		r := mustRun(t, context.Background(), Options{Budget: 2 * time.Second, Concurrency: 1},
			fake("a", block), fake("b", block), fake("c", block))
		if !r.BudgetExceeded || r.Interrupted {
			t.Errorf("BudgetExceeded=%v Interrupted=%v, want true/false", r.BudgetExceeded, r.Interrupted)
		}
		for _, c := range r.Collectors {
			if c.Status != StatusTimeout {
				t.Errorf("%s: status=%s, want timeout", c.Name, c.Status)
			}
		}
		if len(r.Collectors) != 3 {
			t.Errorf("reports = %d, want 3 (unstarted collectors must still be reported)", len(r.Collectors))
		}
	})
}

func TestInterruptIsDistinctFromTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		go func() { time.Sleep(time.Second); cancel() }()
		r := mustRun(t, ctx, Options{},
			fake("long", func(ctx context.Context, _ Sink) error { <-ctx.Done(); return ctx.Err() }))
		if !r.Interrupted || r.BudgetExceeded {
			t.Errorf("Interrupted=%v BudgetExceeded=%v, want true/false", r.Interrupted, r.BudgetExceeded)
		}
		if got := report(t, r, "long"); got.Status != StatusCancelled {
			t.Errorf("status=%s, want cancelled", got.Status)
		}
	})
}

func TestStatusClassification(t *testing.T) {
	r := mustRun(t, context.Background(), Options{MaxDegradationsPerCollector: 2},
		fake("unsupported", func(context.Context, Sink) error { return fmt.Errorf("procfs: %w", ErrUnsupported) }),
		fake("failed", func(context.Context, Sink) error { return errors.New("parse error") }),
		fake("degraded", func(_ context.Context, s Sink) error {
			for i := range 5 {
				s.Degrade(Degradation{Scope: fmt.Sprintf("/proc/%d/fd", i), Reason: ReasonPermission})
			}
			return nil
		}),
		fake("ok", func(context.Context, Sink) error { return nil }),
	)
	want := map[string]Status{"unsupported": StatusUnsupported, "failed": StatusFailed, "degraded": StatusDegraded, "ok": StatusOK}
	for name, st := range want {
		if got := report(t, r, name); got.Status != st {
			t.Errorf("%s: status=%s, want %s", name, got.Status, st)
		}
	}
	if d := report(t, r, "degraded"); len(d.Degradations) != 2 || d.DroppedDegradations != 3 {
		t.Errorf("degradation cap: kept=%d dropped=%d, want 2/3", len(d.Degradations), d.DroppedDegradations)
	}
	// ok=1, degraded=0.5, failed=0; unsupported excluded => 1.5/3.
	if c := r.Coverage(); c != 0.5 {
		t.Errorf("coverage = %v, want 0.5", c)
	}
}

func TestSinkStampsIdentityAndRejectsInvalid(t *testing.T) {
	r := mustRun(t, context.Background(), Options{},
		fake("real", func(_ context.Context, s Sink) error {
			f := mkFinding("spoof", finding.SeverityHigh)
			f.Collector, f.Engine = "someone-else", finding.EngineAudit
			s.Emit(f)
			s.Emit(finding.Finding{RuleID: "", Title: "no rule"})
			bad := mkFinding("bad.attack", finding.SeverityLow)
			bad.Techniques = []string{"T0000"}
			s.Emit(bad)
			return nil
		}))
	if len(r.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(r.Findings))
	}
	if f := r.Findings[0]; f.Collector != "real" || f.Engine != finding.EngineHost || f.Fingerprint == "" {
		t.Errorf("identity not stamped: %+v", f)
	}
	if got := report(t, r, "real"); got.RejectedFindings != 2 {
		t.Errorf("rejected = %d, want 2", got.RejectedFindings)
	}
}

func TestSinkDeepCopiesInput(t *testing.T) {
	r := mustRun(t, context.Background(), Options{},
		fake("mutator", func(_ context.Context, s Sink) error {
			f := mkFinding("copy", finding.SeverityLow)
			f.Techniques = []string{"T1014"}
			f.Evidence = map[string]string{"exe": "/tmp/x"}
			s.Emit(f)
			f.Techniques[0] = "T9999"
			f.Evidence["exe"] = "mutated"
			return nil
		}))
	got := r.Findings[0]
	if got.Techniques[0] != "T1014" || got.Evidence["exe"] != "/tmp/x" {
		t.Errorf("collector mutation leaked into result: %+v", got)
	}
}

func TestFindingCap(t *testing.T) {
	r := mustRun(t, context.Background(), Options{MaxFindingsPerCollector: 3},
		fake("noisy", func(_ context.Context, s Sink) error {
			for i := range 10 {
				s.Emit(mkFinding(fmt.Sprintf("r%d", i), finding.SeverityLow))
			}
			return nil
		}))
	got := report(t, r, "noisy")
	if got.Findings != 3 || got.DroppedFindings != 7 {
		t.Errorf("kept=%d dropped=%d, want 3/7", got.Findings, got.DroppedFindings)
	}
}

func TestOutputIsDeterministicAndDeduplicated(t *testing.T) {
	emitter := func(rules ...string) func(context.Context, Sink) error {
		return func(_ context.Context, s Sink) error {
			var wg sync.WaitGroup
			for _, r := range rules {
				wg.Add(1)
				go func() { defer wg.Done(); s.Emit(mkFinding(r, finding.SeverityMedium)) }()
			}
			wg.Wait()
			return nil
		}
	}
	run := func() []string {
		r := mustRun(t, context.Background(), Options{},
			fake("x", emitter("c", "a", "b", "a")),
			fake("y", emitter("e", "d")))
		var ids []string
		for _, f := range r.Findings {
			ids = append(ids, f.Collector+"/"+f.RuleID)
		}
		return ids
	}
	first := run()
	if want := []string{"x/a", "x/b", "x/c", "y/d", "y/e"}; !reflect.DeepEqual(first, want) {
		t.Fatalf("order = %v, want %v", first, want)
	}
	for range 20 {
		if got := run(); !reflect.DeepEqual(got, first) {
			t.Fatalf("non-deterministic output: %v vs %v", got, first)
		}
	}
}

func TestConcurrencyLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var active, peak atomic.Int32
		var cs []Collector
		for i := range 8 {
			cs = append(cs, fake(fmt.Sprintf("c%d", i), func(context.Context, Sink) error {
				n := active.Add(1)
				for {
					p := peak.Load()
					if n <= p || peak.CompareAndSwap(p, n) {
						break
					}
				}
				time.Sleep(100 * time.Millisecond)
				active.Add(-1)
				return nil
			}))
		}
		r := mustRun(t, context.Background(), Options{Concurrency: 2}, cs...)
		if p := peak.Load(); p != 2 {
			t.Errorf("peak concurrency = %d, want 2", p)
		}
		if len(r.Collectors) != 8 {
			t.Errorf("reports = %d, want 8", len(r.Collectors))
		}
	})
}

func TestOnFinishCalledOncePerCollector(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var mu sync.Mutex
		seen := map[string]int{}
		block := func(ctx context.Context, _ Sink) error { <-ctx.Done(); return ctx.Err() }
		mustRun(t, context.Background(), Options{
			Budget: time.Second, Concurrency: 1,
			OnFinish: func(c CollectorReport) { mu.Lock(); seen[c.Name]++; mu.Unlock() },
		}, fake("a", block), fake("b", block))
		if seen["a"] != 1 || seen["b"] != 1 {
			t.Errorf("OnFinish calls = %v, want one each", seen)
		}
	})
}

func TestNewValidation(t *testing.T) {
	ok := fake("a", func(context.Context, Sink) error { return nil })
	cases := map[string][]Collector{
		"duplicate": {ok, fake("a", nil)},
		"empty":     {fake("", nil)},
		"nil":       {nil},
	}
	for name, cs := range cases {
		if _, err := New(Options{}, cs...); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := New(Options{Budget: -time.Second}); err == nil {
		t.Error("negative budget accepted")
	}
}

func TestDegradationFor(t *testing.T) {
	perm := &fs.PathError{Op: "open", Path: "/proc/1/environ", Err: fs.ErrPermission}
	gone := &fs.PathError{Op: "open", Path: "/proc/99/stat", Err: fs.ErrNotExist}
	if d, ok := DegradationFor("/proc/1/environ", perm); !ok || d.Reason != ReasonPermission {
		t.Errorf("permission: %+v ok=%v", d, ok)
	}
	if _, ok := DegradationFor("/proc/99/stat", gone); ok {
		t.Error("ENOENT (process exit race) must not count as a coverage gap")
	}
	if d, _ := DegradationFor("x", errors.New("weird")); d.Reason != ReasonError {
		t.Errorf("generic error reason = %s", d.Reason)
	}
}

func TestCoverageWithNoApplicableCollectors(t *testing.T) {
	r := mustRun(t, context.Background(), Options{},
		fake("u", func(context.Context, Sink) error { return ErrUnsupported }))
	if r.Coverage() != 0 || r.Observed() {
		t.Errorf("coverage=%v observed=%v, want 0/false", r.Coverage(), r.Observed())
	}
}
