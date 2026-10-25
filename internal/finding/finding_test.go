package finding

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"
)

func TestSeverityRoundTrip(t *testing.T) {
	for s := SeverityInfo; s <= SeverityCritical; s++ {
		b, err := s.MarshalText()
		if err != nil {
			t.Fatalf("%v: %v", s, err)
		}
		var got Severity
		if err := got.UnmarshalText(bytes.ToUpper(b)); err != nil || got != s {
			t.Errorf("round trip %v -> %q -> %v (err %v)", s, b, got, err)
		}
	}
	if _, err := Severity(42).MarshalText(); err == nil {
		t.Error("invalid severity marshalled without error")
	}
	if _, err := ParseSeverity("severe"); err == nil {
		t.Error("unknown severity parsed without error")
	}
}

func TestSecurityScoreBands(t *testing.T) {
	// GitHub code scanning bands; a drift here silently mis-ranks alerts.
	bands := map[Severity][2]float64{
		SeverityCritical: {9.0, 10.0},
		SeverityHigh:     {7.0, 8.9},
		SeverityMedium:   {4.0, 6.9},
		SeverityLow:      {0.1, 3.9},
	}
	for s, b := range bands {
		if v := s.SecurityScore(); v < b[0] || v > b[1] {
			t.Errorf("%v score %.1f outside GitHub band [%.1f, %.1f]", s, v, b[0], b[1])
		}
	}
}

func validFinding() Finding {
	return Finding{RuleID: "host.process.deleted-exe", Title: "t", Severity: SeverityHigh, Techniques: []string{"T1070.004"}}
}

func TestValidate(t *testing.T) {
	cases := map[string]func(*Finding){
		"empty rule":        func(f *Finding) { f.RuleID = "" },
		"whitespace rule":   func(f *Finding) { f.RuleID = "a b" },
		"empty title":       func(f *Finding) { f.Title = "" },
		"bad severity":      func(f *Finding) { f.Severity = 99 },
		"bad confidence":    func(f *Finding) { f.Confidence = 99 },
		"unknown technique": func(f *Finding) { f.Techniques = []string{"T0000"} },
		"negative line":     func(f *Finding) { f.Location.StartLine = -1 },
		"inverted range":    func(f *Finding) { f.Location.StartLine, f.Location.EndLine = 5, 2 },
		"huge evidence":     func(f *Finding) { f.Evidence = map[string]string{"k": strings.Repeat("x", maxEvidenceLen)} },
	}
	base := validFinding()
	if err := base.Validate(); err != nil {
		t.Fatalf("baseline finding invalid: %v", err)
	}
	for name, mutate := range cases {
		f := validFinding()
		mutate(&f)
		if f.Validate() == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

func TestFingerprintIsUnambiguous(t *testing.T) {
	if Fingerprint("ab", "c") == Fingerprint("a", "bc") {
		t.Fatal("length prefixing failed: concatenation collision")
	}
	if Fingerprint("x") != Fingerprint("x") {
		t.Fatal("fingerprint not deterministic")
	}
}

func TestDefaultFingerprintIgnoresLineShift(t *testing.T) {
	a, b := validFinding(), validFinding()
	a.Location = Location{Path: "src/app.go", StartLine: 10}
	b.Location = Location{Path: "src/app.go", StartLine: 42}
	if a.DefaultFingerprint() != b.DefaultFingerprint() {
		t.Error("line shift changed fingerprint; baselines would churn")
	}
}

func TestCompareOrdersBySeverityFirst(t *testing.T) {
	fs := []Finding{
		{RuleID: "b", Severity: SeverityLow},
		{RuleID: "a", Severity: SeverityCritical},
		{RuleID: "c", Severity: SeverityHigh, Location: Location{Path: "z"}},
		{RuleID: "c", Severity: SeverityHigh, Location: Location{Path: "a"}},
	}
	slices.SortFunc(fs, func(a, b Finding) int { return Compare(&a, &b) })
	got := []string{fs[0].RuleID, fs[1].Location.Path, fs[2].Location.Path, fs[3].RuleID}
	want := []string{"a", "a", "z", "b"}
	if !slices.Equal(got, want) {
		t.Errorf("order = %v, want %v", got, want)
	}
}

func TestRiskDiscountsConfidence(t *testing.T) {
	hi := Finding{Severity: SeverityCritical, Confidence: ConfidenceHigh}
	lo := Finding{Severity: SeverityCritical, Confidence: ConfidenceLow}
	info := Finding{Severity: SeverityInfo, Confidence: ConfidenceHigh}
	if !(hi.Risk() > lo.Risk() && lo.Risk() > info.Risk()) {
		t.Errorf("risk ordering broken: hi=%.2f lo=%.2f info=%.2f", hi.Risk(), lo.Risk(), info.Risk())
	}
}

func TestSecretNeverLeaks(t *testing.T) {
	const raw = "AKIAIOSFODNN7EXAMPLE"
	s := Secret(raw)
	outputs := map[string]string{}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%10s"} {
		outputs[verb] = fmt.Sprintf(verb, s)
	}
	outputs["struct %+v"] = fmt.Sprintf("%+v", struct{ K Secret }{s})
	j, _ := json.Marshal(map[string]Secret{"k": s})
	outputs["json"] = string(j)
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("m", "k", s)
	outputs["slog"] = buf.String()

	for where, out := range outputs {
		if strings.Contains(out, raw) || strings.Contains(out, fmt.Sprintf("%x", raw)) {
			t.Errorf("%s leaked raw secret: %s", where, out)
		}
	}
	if s.Reveal() != raw {
		t.Error("Reveal must return the raw value")
	}
}

func TestRedactShortValuesRevealNothing(t *testing.T) {
	if got := Redact("hunter2"); strings.Contains(got, "hunt") {
		t.Errorf("short secret prefix leaked: %s", got)
	}
	if got := Redact("ghp_abcdefghijklmnopqrstuvwxyz0123456789"); !strings.HasPrefix(got, "ghp_") {
		t.Errorf("provider prefix not preserved: %s", got)
	}
}
