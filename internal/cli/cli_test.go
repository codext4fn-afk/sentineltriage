package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codext4fn-afk/sentineltriage/internal/config"
	"github.com/codext4fn-afk/sentineltriage/internal/engine"
	"github.com/codext4fn-afk/sentineltriage/internal/finding"
	"github.com/codext4fn-afk/sentineltriage/internal/report/jsonout"
)

func TestDecidePrecedence(t *testing.T) {
	ok := engine.CollectorReport{Name: "a", Status: engine.StatusOK}
	degraded := engine.CollectorReport{Name: "a", Status: engine.StatusDegraded}
	failed := engine.CollectorReport{Name: "b", Status: engine.StatusFailed}
	high := []finding.Finding{{Severity: finding.SeverityHigh}}
	low := []finding.Finding{{Severity: finding.SeverityLow}}

	cases := []struct {
		name     string
		r        engine.Result
		failOn   finding.Severity
		minCov   float64
		writeErr error
		want     ExitCode
	}{
		{"clean", engine.Result{Collectors: []engine.CollectorReport{ok}}, finding.SeverityHigh, 0, nil, ExitClean},
		{"below threshold", engine.Result{Collectors: []engine.CollectorReport{ok}, Findings: low}, finding.SeverityHigh, 0, nil, ExitClean},
		{"at threshold", engine.Result{Collectors: []engine.CollectorReport{ok}, Findings: high}, finding.SeverityHigh, 0, nil, ExitFindings},
		{"lowered threshold", engine.Result{Collectors: []engine.CollectorReport{ok}, Findings: low}, finding.SeverityLow, 0, nil, ExitFindings},
		{"interrupt beats findings", engine.Result{Interrupted: true, Findings: high}, finding.SeverityHigh, 0, nil, ExitInterrupted},
		{"write error beats findings", engine.Result{Collectors: []engine.CollectorReport{ok}, Findings: high}, finding.SeverityHigh, 0, errors.New("disk full"), ExitRuntime},
		{"findings beat nothing-observed", engine.Result{Collectors: []engine.CollectorReport{failed}, Findings: high}, finding.SeverityHigh, 0, nil, ExitFindings},
		{"nothing observed is never clean", engine.Result{Collectors: []engine.CollectorReport{failed}}, finding.SeverityHigh, 0, nil, ExitRuntime},
		{"no collectors is never clean", engine.Result{}, finding.SeverityHigh, 0, nil, ExitRuntime},
		{"coverage gate", engine.Result{Collectors: []engine.CollectorReport{degraded, failed}}, finding.SeverityHigh, 0.5, nil, ExitCoverage},
		{"coverage met", engine.Result{Collectors: []engine.CollectorReport{ok, degraded}}, finding.SeverityHigh, 0.75, nil, ExitClean},
	}
	for _, c := range cases {
		if got, reason := Decide(&c.r, c.failOn, c.minCov, c.writeErr); got != c.want {
			t.Errorf("%s: got %d (%s), want %d", c.name, got, reason, c.want)
		}
	}
}

type stubCollector struct {
	name     string
	findings []finding.Finding
	err      error
}

func (s stubCollector) Name() string           { return s.name }
func (s stubCollector) Engine() finding.Engine { return finding.EngineAudit }
func (s stubCollector) Run(_ context.Context, sink engine.Sink) error {
	for _, f := range s.findings {
		sink.Emit(f)
	}
	return s.err
}

type harness struct {
	app            *App
	stdout, stderr *bytes.Buffer
	dir            string
}

func newHarness(t *testing.T, cs ...engine.Collector) *harness {
	t.Helper()
	h := &harness{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, dir: t.TempDir()}
	h.app = &App{
		Stdout:   h.stdout,
		Stderr:   h.stderr,
		Getenv:   func(string) string { return "" },
		Hostname: func() (string, error) { return "testhost", nil },
		Factories: map[finding.Engine]Factory{
			finding.EngineAudit: func(*config.Config, *slog.Logger) ([]engine.Collector, error) { return cs, nil },
		},
	}
	return h
}

func (h *harness) run(t *testing.T, args ...string) ExitCode {
	t.Helper()
	base := []string{"--engine", "audit", "--output-dir", filepath.Join(h.dir, "out")}
	return h.app.Run(context.Background(), append(base, args...))
}

func secretFinding(sev finding.Severity) finding.Finding {
	return finding.Finding{RuleID: "audit.secret.aws", Title: "AWS key", Severity: sev, Location: finding.Location{Path: "app.env", StartLine: 3}}
}

func TestRunWritesReportAndBreaksPipelineOnHigh(t *testing.T) {
	h := newHarness(t, stubCollector{name: "audit.secrets", findings: []finding.Finding{secretFinding(finding.SeverityHigh)}})
	if code := h.run(t); code != ExitFindings {
		t.Fatalf("exit = %d, want 1; stderr:\n%s", code, h.stderr)
	}
	b, err := os.ReadFile(filepath.Join(h.dir, "out", "sentinel.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc jsonout.Document
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Summary.Total != 1 || !doc.Summary.ThresholdBreached || doc.Run.Hostname != "testhost" {
		t.Errorf("unexpected document: %+v", doc.Summary)
	}
	if !strings.Contains(h.stdout.String(), "audit.secret.aws") {
		t.Errorf("summary missing finding:\n%s", h.stdout)
	}
}

func TestRunFailOnOverride(t *testing.T) {
	h := newHarness(t, stubCollector{name: "audit.secrets", findings: []finding.Finding{secretFinding(finding.SeverityHigh)}})
	if code := h.run(t, "--fail-on=critical"); code != ExitClean {
		t.Fatalf("exit = %d, want 0", code)
	}
}

func TestRunStdoutJSONIsPure(t *testing.T) {
	h := newHarness(t, stubCollector{name: "audit.secrets"})
	if code := h.run(t, "-f", "json", "--log-level", "debug", "--log-format", "json"); code != ExitClean {
		t.Fatalf("exit = %d, stderr:\n%s", code, h.stderr)
	}
	var doc jsonout.Document
	if err := json.Unmarshal(h.stdout.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not a single JSON document (logs or UI leaked in?): %v\n%s", err, h.stdout)
	}
	if !strings.Contains(h.stderr.String(), `"msg":"run finished"`) {
		t.Errorf("structured logs not routed to stderr:\n%s", h.stderr)
	}
}

func TestRunUsageErrors(t *testing.T) {
	cases := [][]string{
		{"--fail-on", "severe"},
		{"--engine", "kernel"},
		{"--format", "xml"},
		{"--report", "pdf"},
		{"--min-coverage", "2"},
		{"--timeout", "-1s"},
		{"--no-such-flag"},
		{"--config", "does-not-exist.yaml"},
		{"--log-level", "loud"},
	}
	for _, args := range cases {
		h := newHarness(t)
		if code := h.run(t, args...); code != ExitUsage {
			t.Errorf("%v: exit = %d, want 2", args, code)
		}
		if h.stdout.Len() != 0 {
			t.Errorf("%v: usage error wrote to stdout: %q", args, h.stdout)
		}
	}
}

func TestRunNothingObservedIsRuntimeFailure(t *testing.T) {
	h := newHarness(t, stubCollector{name: "audit.secrets", err: errors.New("walker crashed")})
	if code := h.run(t); code != ExitRuntime {
		t.Fatalf("exit = %d, want 3", code)
	}
}

func TestRunNoCollectors(t *testing.T) {
	h := newHarness(t)
	h.app.Factories = nil
	if code := h.run(t); code != ExitRuntime {
		t.Fatalf("exit = %d, want 3", code)
	}
}

func TestRunInterruptedStillWritesReport(t *testing.T) {
	h := newHarness(t, stubCollector{name: "audit.secrets", findings: []finding.Finding{secretFinding(finding.SeverityCritical)}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	code := h.app.Run(ctx, []string{"--engine", "audit", "-o", filepath.Join(h.dir, "out")})
	if code != ExitInterrupted {
		t.Fatalf("exit = %d, want 130", code)
	}
	b, err := os.ReadFile(filepath.Join(h.dir, "out", "sentinel.json"))
	if err != nil {
		t.Fatalf("interrupted run must still write its partial report: %v", err)
	}
	if !bytes.Contains(b, []byte(`"interrupted": true`)) {
		t.Error("report not flagged as interrupted")
	}
}

func TestRunReportWriteFailure(t *testing.T) {
	h := newHarness(t, stubCollector{name: "audit.secrets"})
	blocker := filepath.Join(h.dir, "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if code := h.app.Run(context.Background(), []string{"-e", "audit", "-o", filepath.Join(blocker, "sub")}); code != ExitRuntime {
		t.Fatalf("exit = %d, want 3", code)
	}
}

func TestHelpAndVersion(t *testing.T) {
	h := newHarness(t)
	if code := h.app.Run(context.Background(), []string{"--help"}); code != ExitClean {
		t.Errorf("--help exit = %d", code)
	}
	if !strings.Contains(h.stderr.String(), "Exit status:") {
		t.Error("help text missing exit-code matrix")
	}
	if code := h.app.Run(context.Background(), []string{"-V"}); code != ExitClean || !strings.HasPrefix(h.stdout.String(), "sentinel ") {
		t.Errorf("-V exit=%d out=%q", code, h.stdout)
	}
}

func TestPOSIXFlagForms(t *testing.T) {
	h := newHarness(t, stubCollector{name: "audit.secrets"})
	// Bundled short flags, attached values, and "--" terminating option parsing.
	code := h.app.Run(context.Background(), []string{"-qj2", "-eaudit", "-o", filepath.Join(h.dir, "o"), "--print-config", "--", "-weird-dir"})
	if code != ExitClean {
		t.Fatalf("exit = %d, stderr:\n%s", code, h.stderr)
	}
	out := h.stdout.String()
	for _, want := range []string{"concurrency: 2", "- -weird-dir", "enabled: false"} {
		if !strings.Contains(out, want) {
			t.Errorf("effective config missing %q:\n%s", want, out)
		}
	}
}
