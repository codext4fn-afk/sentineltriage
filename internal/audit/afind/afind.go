// Package afind is a fluent constructor for audit findings. It lives in its
// own leaf package so every analyzer package can share it without importing
// the audit collector, which in turn imports the analyzers.
package afind

import "github.com/codext4fn-afk/sentineltriage/internal/finding"

// B accumulates a Finding. It is a value type; each method returns an updated
// copy, so a B must not be branched after Evidence has allocated its map
// (both copies would then share it). Analyzers build one B per finding, which
// keeps that safe.
type B struct{ f finding.Finding }

// New starts a finding with the fields every audit result requires.
func New(rule, title string, sev finding.Severity, conf finding.Confidence) B {
	return B{finding.Finding{RuleID: rule, Title: title, Severity: sev, Confidence: conf}}
}

// Path sets the scanned-relative file path.
func (b B) Path(p string) B { b.f.Location.Path = p; return b }

// Line sets the 1-based start line.
func (b B) Line(n int) B { b.f.Location.StartLine = n; return b }

// Artifact sets a non-file location descriptor.
func (b B) Artifact(a string) B { b.f.Location.Artifact = a; return b }

// Evidence adds a key/value pair rendered verbatim into reports.
func (b B) Evidence(k, v string) B {
	if b.f.Evidence == nil {
		b.f.Evidence = map[string]string{}
	}
	b.f.Evidence[k] = v
	return b
}

// Tech appends ATT&CK technique IDs; invalid IDs are rejected later by the
// engine's finding validation.
func (b B) Tech(ids ...string) B {
	b.f.Techniques = append(b.f.Techniques, ids...)
	return b
}

// Fix sets the remediation guidance.
func (b B) Fix(s string) B { b.f.Remediation = s; return b }

// Desc sets a longer description.
func (b B) Desc(s string) B { b.f.Description = s; return b }

// Done returns the assembled Finding.
func (b B) Done() finding.Finding { return b.f }
