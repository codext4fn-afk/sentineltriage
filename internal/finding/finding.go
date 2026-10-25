package finding

import (
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/codext4fn-afk/sentineltriage/internal/attack"
)

// Location pins a finding to either a file region (audit engine) or a live
// host artifact (host engine). Both halves may be set, e.g. a cron file that
// spawns a running PID.
type Location struct {
	// Path is slash-separated. Audit paths are relative to the scan root so
	// that SARIF fingerprints survive checkout-directory changes.
	Path        string `json:"path,omitempty"`
	StartLine   int    `json:"start_line,omitempty"`
	EndLine     int    `json:"end_line,omitempty"`
	StartColumn int    `json:"start_column,omitempty"`
	PID         int    `json:"pid,omitempty"`
	// Artifact names a non-file object such as "socket:tcp/0.0.0.0:4444".
	Artifact string `json:"artifact,omitempty"`
}

// Finding is a single, self-describing security observation.
//
// Evidence values are rendered verbatim into JSON, SARIF, HTML, and logs.
// Anything derived from a credential must be passed through Secret or Redact
// before it is placed there.
type Finding struct {
	RuleID      string            `json:"rule_id"`
	Title       string            `json:"title"`
	Description string            `json:"description,omitempty"`
	Severity    Severity          `json:"severity"`
	Confidence  Confidence        `json:"confidence"`
	Engine      Engine            `json:"engine"`
	Collector   string            `json:"collector"`
	Techniques  []string          `json:"attack_techniques,omitempty"`
	Location    Location          `json:"location"`
	Evidence    map[string]string `json:"evidence,omitempty"`
	Remediation string            `json:"remediation,omitempty"`
	Fingerprint string            `json:"fingerprint"`
}

const (
	maxRuleIDLen   = 128
	maxTitleLen    = 512
	maxEvidenceLen = 4096
	maxEvidenceKV  = 32
)

// Validate enforces the invariants reporters depend on. Collectors are treated
// as untrusted producers: a malformed finding is rejected at the engine
// boundary rather than corrupting a SARIF upload downstream.
func (f *Finding) Validate() error {
	var errs []error
	if f.RuleID == "" || len(f.RuleID) > maxRuleIDLen || strings.ContainsAny(f.RuleID, " \t\r\n") {
		errs = append(errs, fmt.Errorf("rule_id %q must be 1-%d chars without whitespace", f.RuleID, maxRuleIDLen))
	}
	if f.Title == "" || len(f.Title) > maxTitleLen {
		errs = append(errs, fmt.Errorf("title must be 1-%d chars", maxTitleLen))
	}
	if !f.Severity.Valid() {
		errs = append(errs, fmt.Errorf("invalid severity %d", f.Severity))
	}
	if !f.Confidence.Valid() {
		errs = append(errs, fmt.Errorf("invalid confidence %d", f.Confidence))
	}
	if err := attack.Validate(f.Techniques); err != nil {
		errs = append(errs, err)
	}
	if f.Location.StartLine < 0 || f.Location.EndLine < 0 || f.Location.StartColumn < 0 {
		errs = append(errs, errors.New("location lines and columns must be non-negative"))
	}
	if f.Location.EndLine != 0 && f.Location.EndLine < f.Location.StartLine {
		errs = append(errs, errors.New("location end_line precedes start_line"))
	}
	if len(f.Evidence) > maxEvidenceKV {
		errs = append(errs, fmt.Errorf("evidence has %d entries, max %d", len(f.Evidence), maxEvidenceKV))
	}
	for k, v := range f.Evidence {
		if len(k)+len(v) > maxEvidenceLen {
			errs = append(errs, fmt.Errorf("evidence %q exceeds %d bytes", k, maxEvidenceLen))
		}
	}
	return errors.Join(errs...)
}

// Risk returns a 0–10 Prowler-style priority score combining impact with
// evidential confidence.
func (f *Finding) Risk() float64 {
	return f.Severity.SecurityScore() * f.Confidence.factor()
}

// Fingerprint derives a stable identifier from the given components. Each
// part is length-prefixed so ("ab","c") and ("a","bc") cannot collide.
//
// Callers fingerprinting a secret must pass a digest of it, never the raw
// value: the fingerprint is published in SARIF and baseline files.
func Fingerprint(parts ...string) string {
	h := sha256.New()
	var n [8]byte
	for _, p := range parts {
		binary.BigEndian.PutUint64(n[:], uint64(len(p)))
		h.Write(n[:])
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// DefaultFingerprint is applied when a collector leaves Fingerprint empty. Line
// numbers are deliberately excluded so that inserting code above a finding
// does not resurrect a baselined issue. Evidence is included, in key order, to
// keep distinct findings of one rule in one file apart (two containers in the
// same manifest, two stages in one Dockerfile); de-duplication would otherwise
// merge them.
func (f *Finding) DefaultFingerprint() string {
	parts := []string{f.RuleID, f.Location.Path, f.Location.Artifact}
	keys := make([]string, 0, len(f.Evidence))
	for k := range f.Evidence {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		parts = append(parts, k, f.Evidence[k])
	}
	return Fingerprint(parts...)
}

// Compare orders findings for deterministic output: highest severity first,
// then by location and rule. Determinism is required for diffable SARIF and
// reproducible baselines, not merely aesthetics.
func Compare(a, b *Finding) int {
	return cmp.Or(
		cmp.Compare(b.Severity, a.Severity),
		cmp.Compare(b.Confidence, a.Confidence),
		cmp.Compare(a.Location.Path, b.Location.Path),
		cmp.Compare(a.Location.StartLine, b.Location.StartLine),
		cmp.Compare(a.Location.PID, b.Location.PID),
		cmp.Compare(a.Location.Artifact, b.Location.Artifact),
		cmp.Compare(a.RuleID, b.RuleID),
		cmp.Compare(a.Fingerprint, b.Fingerprint),
	)
}
