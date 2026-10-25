// Package sarif renders findings as SARIF 2.1.0 for GitHub code scanning and
// other SARIF consumers. The structs model only the subset of the schema this
// tool emits; every field present is one a consumer reads.
package sarif

import (
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/codext4fn-afk/sentineltriage/internal/attack"
	"github.com/codext4fn-afk/sentineltriage/internal/engine"
	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

const (
	schemaURI      = "https://json.schemastore.org/sarif-2.1.0.json"
	version        = "2.1.0"
	informationURI = "https://github.com/codext4fn-afk/sentineltriage"
	// srcRoot is the base id for repository-relative paths; GitHub resolves
	// results against the checkout when this id is used.
	srcRoot = "SRCROOT"
)

// Log is the SARIF root object.
type Log struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool        tool         `json:"tool"`
	Results     []result     `json:"results"`
	Invocations []invocation `json:"invocations"`
	Properties  runProps     `json:"properties"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationURI string `json:"informationUri"`
	Rules          []rule `json:"rules"`
}

type rule struct {
	ID                   string     `json:"id"`
	Name                 string     `json:"name"`
	ShortDescription     text       `json:"shortDescription"`
	FullDescription      *text      `json:"fullDescription,omitempty"`
	Help                 *text      `json:"help,omitempty"`
	HelpURI              string     `json:"helpUri,omitempty"`
	DefaultConfiguration ruleConfig `json:"defaultConfiguration"`
	Properties           ruleProps  `json:"properties"`
}

type ruleConfig struct {
	Level string `json:"level"`
}

type ruleProps struct {
	Tags             []string `json:"tags,omitempty"`
	SecuritySeverity string   `json:"security-severity"`
}

type result struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             text              `json:"message"`
	Locations           []location        `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          resultProps       `json:"properties"`
}

type resultProps struct {
	SecuritySeverity string   `json:"security-severity"`
	Confidence       string   `json:"confidence"`
	Engine           string   `json:"engine"`
	Collector        string   `json:"collector"`
	Techniques       []string `json:"attack-techniques,omitempty"`
}

type location struct {
	PhysicalLocation physicalLocation `json:"physicalLocation"`
}

type physicalLocation struct {
	ArtifactLocation artifactLocation `json:"artifactLocation"`
	Region           *region          `json:"region,omitempty"`
}

type artifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type region struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
}

type text struct {
	Text string `json:"text"`
}

type invocation struct {
	ExecutionSuccessful bool `json:"executionSuccessful"`
	ExitCode            int  `json:"exitCode"`
}

type runProps struct {
	ATTACKVersion  string  `json:"attackVersion"`
	Coverage       float64 `json:"coverage"`
	Interrupted    bool    `json:"interrupted"`
	BudgetExceeded bool    `json:"budgetExceeded"`
}

// Meta carries invocation context the engine Result does not hold.
type Meta struct {
	ToolVersion string
	ExitCode    int
	// IncludeHost admits findings with no source-file location. Off by default:
	// code scanning is organized around files in the repository.
	IncludeHost bool
}

// Build projects a Result into a SARIF Log. Rules are emitted once, in sorted
// order, and results reference them by index. Output is deterministic so that
// SARIF diffs in review reflect real finding changes, not reordering.
func Build(r *engine.Result, m Meta) Log {
	type ruleAgg struct {
		sev        finding.Severity
		conf       finding.Confidence
		title      string
		desc       string
		techniques []string
	}
	agg := map[string]*ruleAgg{}
	var included []*finding.Finding

	for i := range r.Findings {
		f := &r.Findings[i]
		// Code scanning is organized around repository files, so host-engine
		// results are excluded unless explicitly opted in, regardless of
		// whether they carry an on-disk path.
		if f.Engine == finding.EngineHost && !m.IncludeHost {
			continue
		}
		if _, _, ok := locate(f); !ok {
			continue
		}
		included = append(included, f)
		if _, seen := agg[f.RuleID]; !seen {
			agg[f.RuleID] = &ruleAgg{sev: f.Severity, conf: f.Confidence, title: f.Title, desc: f.Description, techniques: f.Techniques}
		}
	}

	ruleIDs := make([]string, 0, len(agg))
	for id := range agg {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)
	ruleIndex := make(map[string]int, len(ruleIDs))
	rules := make([]rule, 0, len(ruleIDs))
	for i, id := range ruleIDs {
		ruleIndex[id] = i
		a := agg[id]
		rules = append(rules, rule{
			ID:                   id,
			Name:                 ruleName(id),
			ShortDescription:     text{a.title},
			FullDescription:      optText(a.desc),
			HelpURI:              helpURI(a.techniques),
			DefaultConfiguration: ruleConfig{Level: level(a.sev)},
			Properties: ruleProps{
				Tags:             append([]string{"security"}, a.techniques...),
				SecuritySeverity: severityScore(a.sev),
			},
		})
	}

	results := make([]result, 0, len(included))
	for _, f := range included {
		uri, abs, _ := locate(f)
		loc := location{PhysicalLocation: physicalLocation{
			ArtifactLocation: artifactLocation{URI: uri},
			Region:           regionOf(f.Location),
		}}
		if !abs {
			loc.PhysicalLocation.ArtifactLocation.URIBaseID = srcRoot
		}
		results = append(results, result{
			RuleID:    f.RuleID,
			RuleIndex: ruleIndex[f.RuleID],
			Level:     level(f.Severity),
			Message:   text{messageText(f)},
			Locations: []location{loc},
			PartialFingerprints: map[string]string{
				"sentinelFingerprint/v1": f.Fingerprint,
			},
			Properties: resultProps{
				SecuritySeverity: severityScore(f.Severity),
				Confidence:       f.Confidence.String(),
				Engine:           string(f.Engine),
				Collector:        f.Collector,
				Techniques:       f.Techniques,
			},
		})
	}

	return Log{
		Schema:  schemaURI,
		Version: version,
		Runs: []run{{
			Tool: tool{Driver: driver{
				Name:           "SentinelTriage",
				Version:        m.ToolVersion,
				InformationURI: informationURI,
				Rules:          rules,
			}},
			Results: results,
			Invocations: []invocation{{
				// executionSuccessful reflects whether the scan ran, not
				// whether it was clean: a run that completed and found issues
				// is still a successful invocation.
				ExecutionSuccessful: !r.Interrupted,
				ExitCode:            m.ExitCode,
			}},
			Properties: runProps{
				ATTACKVersion:  attack.Version,
				Coverage:       r.Coverage(),
				Interrupted:    r.Interrupted,
				BudgetExceeded: r.BudgetExceeded,
			},
		}},
	}
}

// Write encodes the log as indented JSON.
func Write(w io.Writer, log Log) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// locate resolves a finding's SARIF artifact URI. abs reports an absolute
// path, which must not carry a uriBaseId. A finding with no path at all gets a
// synthesized opaque location so the result stays schema-valid.
func locate(f *finding.Finding) (uri string, abs bool, ok bool) {
	p := f.Location.Path
	switch {
	case p == "":
		return "sentinel://host/" + sanitize(f.Collector), true, true
	case strings.HasPrefix(p, "/"):
		return "file://" + p, true, true
	default:
		return strings.TrimPrefix(p, "./"), false, true
	}
}

func regionOf(l finding.Location) *region {
	if l.StartLine <= 0 {
		return nil
	}
	return &region{StartLine: l.StartLine, StartColumn: l.StartColumn, EndLine: l.EndLine}
}

// level maps severity to the SARIF result-level enum.
func level(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical, finding.SeverityHigh:
		return "error"
	case finding.SeverityMedium:
		return "warning"
	case finding.SeverityLow:
		return "note"
	default:
		return "none"
	}
}

func severityScore(s finding.Severity) string {
	return strconv.FormatFloat(s.SecurityScore(), 'f', 1, 64)
}

func messageText(f *finding.Finding) string {
	var b strings.Builder
	b.WriteString(f.Title)
	if f.Remediation != "" {
		b.WriteString("\n\nRemediation: ")
		b.WriteString(f.Remediation)
	}
	if len(f.Techniques) > 0 {
		b.WriteString("\n\nMITRE ATT&CK: ")
		b.WriteString(strings.Join(f.Techniques, ", "))
	}
	return b.String()
}

// ruleName is a PascalCase identifier derived from the dotted rule ID, which
// GitHub shows as the alert's rule name.
func ruleName(id string) string {
	parts := strings.FieldsFunc(id, func(r rune) bool { return r == '.' || r == '-' })
	for i, p := range parts {
		if p != "" {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, "")
}

func helpURI(techniques []string) string {
	if len(techniques) == 0 {
		return informationURI
	}
	if t, ok := attack.Lookup(techniques[0]); ok {
		return t.URL()
	}
	return informationURI
}

func optText(s string) *text {
	if s == "" {
		return nil
	}
	return &text{s}
}

func sanitize(s string) string {
	if s == "" {
		return "unknown"
	}
	return strings.Map(func(r rune) rune {
		if r == '/' || r == ' ' {
			return '-'
		}
		return r
	}, s)
}
