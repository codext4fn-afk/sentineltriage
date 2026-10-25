// Package finding defines the immutable result model shared by every engine,
// reporter, and exit-code decision. It has no dependencies beyond the standard
// library and internal/attack so that collectors cannot drag reporter or UI
// concerns into the data model.
package finding

import (
	"fmt"
	"strings"
)

// Severity is the impact rating of a finding. The zero value is SeverityInfo
// so that an unset field never escalates a pipeline failure.
type Severity uint8

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = [...]string{"info", "low", "medium", "high", "critical"}

// String returns the lowercase canonical name used in configs, flags, and JSON.
func (s Severity) String() string {
	if int(s) < len(severityNames) {
		return severityNames[s]
	}
	return fmt.Sprintf("severity(%d)", uint8(s))
}

// Valid reports whether s is one of the declared severities.
func (s Severity) Valid() bool { return int(s) < len(severityNames) }

// ParseSeverity converts a case-insensitive name into a Severity.
func ParseSeverity(name string) (Severity, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	for i, v := range severityNames {
		if v == n {
			return Severity(i), nil
		}
	}
	return 0, fmt.Errorf("unknown severity %q (want one of %s)", name, strings.Join(severityNames[:], ", "))
}

// MarshalText implements encoding.TextMarshaler. JSON and YAML both route
// through it, keeping a single wire representation.
func (s Severity) MarshalText() ([]byte, error) {
	if !s.Valid() {
		return nil, fmt.Errorf("cannot marshal invalid severity %d", uint8(s))
	}
	return []byte(s.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (s *Severity) UnmarshalText(b []byte) error {
	v, err := ParseSeverity(string(b))
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// SecurityScore maps s onto the 0.0–10.0 scale GitHub code scanning reads from
// the SARIF "security-severity" property. Values sit mid-band so that the
// GitHub thresholds (>=9.0 critical, >=7.0 high, >=4.0 medium, >0 low) are not
// sensitive to float rounding.
func (s Severity) SecurityScore() float64 {
	switch s {
	case SeverityCritical:
		return 9.5
	case SeverityHigh:
		return 8.0
	case SeverityMedium:
		return 5.5
	case SeverityLow:
		return 2.0
	default:
		return 0.0
	}
}

// Confidence expresses how strongly the evidence supports the finding,
// independent of its impact. It feeds risk scoring and ATT&CK mapping policy.
type Confidence uint8

const (
	ConfidenceLow Confidence = iota
	ConfidenceMedium
	ConfidenceHigh
)

var confidenceNames = [...]string{"low", "medium", "high"}

// String returns the lowercase canonical name.
func (c Confidence) String() string {
	if int(c) < len(confidenceNames) {
		return confidenceNames[c]
	}
	return fmt.Sprintf("confidence(%d)", uint8(c))
}

// Valid reports whether c is one of the declared confidence levels.
func (c Confidence) Valid() bool { return int(c) < len(confidenceNames) }

// ParseConfidence converts a case-insensitive name into a Confidence.
func ParseConfidence(name string) (Confidence, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	for i, v := range confidenceNames {
		if v == n {
			return Confidence(i), nil
		}
	}
	return 0, fmt.Errorf("unknown confidence %q (want one of %s)", name, strings.Join(confidenceNames[:], ", "))
}

// MarshalText implements encoding.TextMarshaler.
func (c Confidence) MarshalText() ([]byte, error) {
	if !c.Valid() {
		return nil, fmt.Errorf("cannot marshal invalid confidence %d", uint8(c))
	}
	return []byte(c.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (c *Confidence) UnmarshalText(b []byte) error {
	v, err := ParseConfidence(string(b))
	if err != nil {
		return err
	}
	*c = v
	return nil
}

// factor discounts impact by evidential strength. Low confidence keeps a
// non-zero weight: a weak signal of a critical issue still outranks a certain
// informational one.
func (c Confidence) factor() float64 {
	switch c {
	case ConfidenceHigh:
		return 1.0
	case ConfidenceMedium:
		return 0.7
	default:
		return 0.4
	}
}

// Engine identifies which top-level engine produced a finding.
type Engine string

const (
	EngineHost  Engine = "host"
	EngineAudit Engine = "audit"
)

// ParseEngine validates an engine name from user input.
func ParseEngine(name string) (Engine, error) {
	switch e := Engine(strings.ToLower(strings.TrimSpace(name))); e {
	case EngineHost, EngineAudit:
		return e, nil
	default:
		return "", fmt.Errorf("unknown engine %q (want host or audit)", name)
	}
}
