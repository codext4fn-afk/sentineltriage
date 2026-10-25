package sarif

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/codext4fn-afk/sentineltriage/internal/engine"
	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

func sampleResult() *engine.Result {
	mk := func(rule, path string, line int, sev finding.Severity, tech ...string) finding.Finding {
		f := finding.Finding{
			RuleID: rule, Title: rule + " title", Description: "why it matters",
			Severity: sev, Confidence: finding.ConfidenceHigh, Engine: finding.EngineAudit,
			Collector: "audit.files", Techniques: tech,
			Location: finding.Location{Path: path, StartLine: line}, Remediation: "fix it",
		}
		f.Fingerprint = f.DefaultFingerprint()
		return f
	}
	return &engine.Result{
		Findings: []finding.Finding{
			mk("drift.k8s.privileged", "deploy/pod.yaml", 12, finding.SeverityCritical, "T1611"),
			mk("drift.dockerfile.unpinned-base", "Dockerfile", 1, finding.SeverityMedium),
			mk("drift.dockerfile.unpinned-base", "svc/Dockerfile", 1, finding.SeverityMedium),
			func() finding.Finding { // host finding with absolute path
				f := mk("host.persistence.ld-preload", "/etc/ld.so.preload", 0, finding.SeverityHigh, "T1574.006")
				f.Engine, f.Collector = finding.EngineHost, "host.persistence"
				return f
			}(),
		},
		Collectors: []engine.CollectorReport{{Name: "audit.files", Status: engine.StatusOK}},
	}
}

func compileSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	path := filepath.Join("testdata", "sarif-2.1.0.json")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open schema (run go test from package dir): %v", err)
	}
	defer f.Close()
	doc, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("sarif.json", doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile("sarif.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return sch
}

func validate(t *testing.T, sch *jsonschema.Schema, raw []byte) {
	t.Helper()
	var inst any
	if err := json.Unmarshal(raw, &inst); err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(inst); err != nil {
		t.Fatalf("SARIF output fails official 2.1.0 schema:\n%v", err)
	}
}

func TestSchemaConformance(t *testing.T) {
	sch := compileSchema(t)
	var buf bytes.Buffer
	if err := Write(&buf, Build(sampleResult(), Meta{ToolVersion: "1.0.0", ExitCode: 1, IncludeHost: true})); err != nil {
		t.Fatal(err)
	}
	validate(t, sch, buf.Bytes())

	// An empty run must also be schema-valid.
	buf.Reset()
	if err := Write(&buf, Build(&engine.Result{}, Meta{ToolVersion: "1.0.0"})); err != nil {
		t.Fatal(err)
	}
	validate(t, sch, buf.Bytes())
}

func decode(t *testing.T, m Meta) Log {
	t.Helper()
	var buf bytes.Buffer
	if err := Write(&buf, Build(sampleResult(), m)); err != nil {
		t.Fatal(err)
	}
	var log Log
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	return log
}

func TestHostFindingsExcludedByDefault(t *testing.T) {
	log := decode(t, Meta{ToolVersion: "1.0.0"})
	for _, r := range log.Runs[0].Results {
		if r.Properties.Engine == "host" {
			t.Error("host finding leaked into SARIF without IncludeHost")
		}
	}
	withHost := decode(t, Meta{ToolVersion: "1.0.0", IncludeHost: true})
	if len(withHost.Runs[0].Results) <= len(log.Runs[0].Results) {
		t.Error("IncludeHost did not add host results")
	}
}

func TestRulesDedupedAndIndexed(t *testing.T) {
	log := decode(t, Meta{ToolVersion: "1.0.0", IncludeHost: true})
	run := log.Runs[0]
	// Four findings, but unpinned-base appears twice -> 3 distinct rules.
	if len(run.Tool.Driver.Rules) != 3 {
		t.Errorf("rules = %d, want 3 (deduped)", len(run.Tool.Driver.Rules))
	}
	for _, res := range run.Results {
		if res.RuleIndex < 0 || res.RuleIndex >= len(run.Tool.Driver.Rules) {
			t.Fatalf("ruleIndex %d out of range", res.RuleIndex)
		}
		if run.Tool.Driver.Rules[res.RuleIndex].ID != res.RuleID {
			t.Errorf("ruleIndex %d points at %q, not %q", res.RuleIndex, run.Tool.Driver.Rules[res.RuleIndex].ID, res.RuleID)
		}
	}
}

func TestSecuritySeverityAndLevel(t *testing.T) {
	log := decode(t, Meta{ToolVersion: "1.0.0", IncludeHost: true})
	byRule := map[string]result{}
	for _, r := range log.Runs[0].Results {
		byRule[r.RuleID] = r
	}
	if r := byRule["drift.k8s.privileged"]; r.Level != "error" || r.Properties.SecuritySeverity != "9.5" {
		t.Errorf("critical mapped wrong: level=%s score=%s", r.Level, r.Properties.SecuritySeverity)
	}
	if r := byRule["drift.dockerfile.unpinned-base"]; r.Level != "warning" {
		t.Errorf("medium -> level %s, want warning", r.Level)
	}
}

func TestLocationURIBaseID(t *testing.T) {
	log := decode(t, Meta{ToolVersion: "1.0.0", IncludeHost: true})
	for _, r := range log.Runs[0].Results {
		al := r.Locations[0].PhysicalLocation.ArtifactLocation
		switch r.RuleID {
		case "host.persistence.ld-preload":
			// Absolute path: no SRCROOT base, file:// scheme.
			if al.URIBaseID != "" || al.URI != "file:///etc/ld.so.preload" {
				t.Errorf("host uri = %q base = %q", al.URI, al.URIBaseID)
			}
		default:
			if al.URIBaseID != srcRoot {
				t.Errorf("%s: repo-relative result missing SRCROOT base", r.RuleID)
			}
		}
	}
}

func TestFingerprintsPresent(t *testing.T) {
	log := decode(t, Meta{ToolVersion: "1.0.0"})
	for _, r := range log.Runs[0].Results {
		if r.PartialFingerprints["sentinelFingerprint/v1"] == "" {
			t.Errorf("%s missing partial fingerprint", r.RuleID)
		}
	}
}

func TestDeterministicOutput(t *testing.T) {
	var a, b bytes.Buffer
	_ = Write(&a, Build(sampleResult(), Meta{ToolVersion: "1.0.0", IncludeHost: true}))
	_ = Write(&b, Build(sampleResult(), Meta{ToolVersion: "1.0.0", IncludeHost: true}))
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Error("SARIF output is not byte-identical across builds")
	}
}
