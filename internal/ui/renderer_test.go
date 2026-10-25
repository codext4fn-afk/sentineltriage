package ui

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/codext4fn-afk/sentineltriage/internal/engine"
	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

func TestPlainWithoutColorEmitsNoEscapes(t *testing.T) {
	var progress, out bytes.Buffer
	p := &Plain{Progress: &progress, Out: &out}
	p.CollectorDone(engine.CollectorReport{Name: "host.process", Status: engine.StatusDegraded, Degradations: []engine.Degradation{{}}})
	p.Summary(RunSummary{Result: &engine.Result{}, ExitCode: 0, Reason: "clean"})
	if strings.Contains(progress.String()+out.String(), "\x1b[") {
		t.Error("ANSI escapes emitted with Color=false; CI logs would be polluted")
	}
	if !strings.Contains(progress.String(), "1 gaps") {
		t.Errorf("degradation count missing: %q", progress.String())
	}
}

func TestPlainSummaryTruncatesFindingList(t *testing.T) {
	var out bytes.Buffer
	r := &engine.Result{}
	for i := range maxListed + 5 {
		r.Findings = append(r.Findings, finding.Finding{RuleID: fmt.Sprintf("r%02d", i), Title: "t", Severity: finding.SeverityLow})
	}
	(&Plain{Progress: &out, Out: &out}).Summary(RunSummary{Result: r, ExitCode: 1, Reason: "x"})
	if !strings.Contains(out.String(), "5 more in the reports") {
		t.Errorf("finding list not truncated:\n%s", out.String())
	}
	if strings.Contains(out.String(), fmt.Sprintf("r%02d", maxListed)) {
		t.Error("finding beyond the display cap was printed")
	}
}
