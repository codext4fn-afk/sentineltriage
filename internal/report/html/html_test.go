package html

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"strings"
	"testing"

	"github.com/codext4fn-afk/sentineltriage/internal/engine"
	"github.com/codext4fn-afk/sentineltriage/internal/finding"
	"github.com/codext4fn-afk/sentineltriage/internal/report/jsonout"
)

func render(t *testing.T, r *engine.Result) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Write(&buf, r, jsonout.Meta{ToolVersion: "1.0.0", FailOn: finding.SeverityHigh}); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestSelfContainedNoExternalResources(t *testing.T) {
	out := render(t, &engine.Result{})
	for _, bad := range []string{"http://", "https://", "src=", "href=", "//cdn", "integrity="} {
		if strings.Contains(out, bad) {
			t.Errorf("report references external/remote resource via %q", bad)
		}
	}
}

func TestCSPHashMatchesEmittedScript(t *testing.T) {
	out := render(t, &engine.Result{})

	// Extract the executable <script> (the one without a type attribute).
	re := regexp.MustCompile(`(?s)<script>(.*?)</script>`)
	m := re.FindStringSubmatch(out)
	if m == nil {
		t.Fatal("no executable <script> block found")
	}
	sum := sha256.Sum256([]byte(m[1]))
	want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	if !strings.Contains(out, "script-src "+want) {
		t.Errorf("CSP script hash does not match emitted script bytes;\nwant %s in CSP", want)
	}

	// And the style block hash.
	reS := regexp.MustCompile(`(?s)<style>(.*?)</style>`)
	ms := reS.FindStringSubmatch(out)
	if ms == nil {
		t.Fatal("no <style> block found")
	}
	ssum := sha256.Sum256([]byte(ms[1]))
	wantS := "'sha256-" + base64.StdEncoding.EncodeToString(ssum[:]) + "'"
	if !strings.Contains(out, "style-src "+wantS) {
		t.Error("CSP style hash does not match emitted style bytes")
	}
}

func TestCSPLocksDownOrigins(t *testing.T) {
	out := render(t, &engine.Result{})
	for _, want := range []string{"default-src 'none'", "base-uri 'none'", "form-action 'none'"} {
		if !strings.Contains(out, want) {
			t.Errorf("CSP missing %q", want)
		}
	}
}

func TestUntrustedContentIsNeutralized(t *testing.T) {
	payload := `</script><img src=x onerror=alert(1)>`
	r := &engine.Result{
		Findings: []finding.Finding{{
			RuleID:   "audit.x",
			Title:    payload,
			Severity: finding.SeverityHigh,
			Engine:   finding.EngineAudit,
			Location: finding.Location{Path: payload, StartLine: 1},
			Evidence: map[string]string{"snippet": payload},
		}},
		Collectors: []engine.CollectorReport{{Name: "audit.files", Status: engine.StatusOK}},
	}
	out := render(t, r)
	// The raw payload must never appear as live markup: the JSON encoder
	// escapes "<" to <, so no literal "<img" or "</script>" from the
	// finding can reach the HTML parser.
	if strings.Contains(out, "<img src=x") {
		t.Error("untrusted markup rendered as live HTML")
	}
	if strings.Count(out, "</script>") != 2 { // data block + app block only
		t.Errorf("payload injected a stray </script>; count=%d", strings.Count(out, "</script>"))
	}
	if !strings.Contains(out, `</script>`) && !strings.Contains(out, `</script`) {
		t.Error("expected the payload to survive only in escaped form inside the JSON block")
	}
}

func TestFindingsDataEmbedded(t *testing.T) {
	r := &engine.Result{
		Findings:   []finding.Finding{{RuleID: "drift.k8s.privileged", Title: "priv", Severity: finding.SeverityCritical, Engine: finding.EngineAudit}},
		Collectors: []engine.CollectorReport{{Name: "c", Status: engine.StatusOK}},
	}
	out := render(t, r)
	if !strings.Contains(out, `"rule_id":"drift.k8s.privileged"`) {
		t.Error("finding data not embedded in report")
	}
	if !strings.Contains(out, `type="application/json"`) {
		t.Error("data not placed in a non-executable JSON block")
	}
}
