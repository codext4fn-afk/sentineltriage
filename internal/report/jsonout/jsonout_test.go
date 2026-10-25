package jsonout

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/codext4fn-afk/sentineltriage/internal/engine"
	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

func TestEmptyResultEncodesArraysNotNull(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, Build(&engine.Result{}, Meta{FailOn: finding.SeverityHigh})); err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"findings", "collectors"} {
		if _, ok := raw[k].([]any); !ok {
			t.Errorf("%s = %v, want []", k, raw[k])
		}
	}
	by := raw["summary"].(map[string]any)["by_severity"].(map[string]any)
	if len(by) != 5 {
		t.Errorf("by_severity has %d keys, want all 5 severities present", len(by))
	}
}

func TestBuildSummaryAndEscaping(t *testing.T) {
	start := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	r := &engine.Result{
		StartedAt: start, FinishedAt: start.Add(1500 * time.Millisecond),
		Findings: []finding.Finding{
			{RuleID: "a", Title: "<script>alert(1)</script>", Severity: finding.SeverityCritical},
			{RuleID: "b", Title: "b", Severity: finding.SeverityLow},
		},
		Collectors: []engine.CollectorReport{{Name: "x", Status: engine.StatusOK}},
	}
	d := Build(r, Meta{ToolVersion: "1.2.3", FailOn: finding.SeverityHigh})
	if !d.Summary.ThresholdBreached || d.Summary.Total != 2 || d.Summary.BySeverity["critical"] != 1 {
		t.Errorf("summary = %+v", d.Summary)
	}
	if d.Run.DurationMS != 1500 || d.Run.Coverage != 1 {
		t.Errorf("run = %+v", d.Run)
	}
	var buf bytes.Buffer
	if err := Write(&buf, d); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "<script>") {
		t.Error("HTML-significant characters not escaped in JSON output")
	}
	if !strings.Contains(buf.String(), `"severity": "critical"`) {
		t.Error("severity not encoded by name")
	}
}
