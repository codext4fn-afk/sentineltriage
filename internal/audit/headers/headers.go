// Package headers checks web-server and hosting configuration for missing
// HTTP security response headers. It is intentionally conservative: it reports
// only on files that already set at least one response header (or are
// dedicated header-config formats), so it never fires on arbitrary config.
package headers

import (
	"path"
	"strings"

	"github.com/codext4fn-afk/sentineltriage/internal/audit/afind"
	"github.com/codext4fn-afk/sentineltriage/internal/audit/walker"
	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

// Analyzer implements audit.Analyzer for HTTP security headers.
type Analyzer struct{}

// Name implements audit.Analyzer.
func (Analyzer) Name() string { return "headers" }

// Applies matches recognized server/hosting config files. The content check in
// Analyze decides whether the file actually configures headers.
func (Analyzer) Applies(f walker.File) bool {
	base := path.Base(f.Rel)
	switch base {
	case "_headers", "vercel.json", "netlify.toml", ".htaccess", "nginx.conf":
		return true
	}
	if strings.Contains(f.Rel, "sites-available/") || strings.Contains(f.Rel, "sites-enabled/") {
		return true
	}
	ext := strings.ToLower(path.Ext(base))
	return ext == ".conf" || ext == ".nginx" || ext == ".htaccess"
}

type header struct {
	rule, canonical, label string
	severity               finding.Severity
	// also accepts an alternative directive (CSP frame-ancestors covers
	// X-Frame-Options).
	alt string
}

var recommended = []header{
	{"headers.missing-csp", "Content-Security-Policy", "Content-Security-Policy", finding.SeverityHigh, ""},
	{"headers.missing-hsts", "Strict-Transport-Security", "Strict-Transport-Security (HSTS)", finding.SeverityHigh, ""},
	{"headers.missing-nosniff", "X-Content-Type-Options", "X-Content-Type-Options: nosniff", finding.SeverityMedium, ""},
	{"headers.missing-frame-options", "X-Frame-Options", "X-Frame-Options / CSP frame-ancestors", finding.SeverityMedium, "frame-ancestors"},
	{"headers.missing-referrer-policy", "Referrer-Policy", "Referrer-Policy", finding.SeverityLow, ""},
}

// directiveMarkers indicate a file sets response headers.
var directiveMarkers = []string{"add_header", "header set", "header always set", `"headers"`, "[[headers]]"}

// Analyze implements audit.Analyzer.
func (Analyzer) Analyze(f walker.File, emit func(finding.Finding)) {
	lower := strings.ToLower(string(f.Content))
	base := path.Base(f.Rel)
	dedicated := base == "_headers" || base == "vercel.json" || base == "netlify.toml"

	anchor, sets := firstDirectiveLine(f.Content, lower)
	if !dedicated && !sets {
		// A plain .conf that configures no headers is not evidence of a web
		// endpoint; staying silent avoids a flood of false positives.
		return
	}

	for _, h := range recommended {
		if strings.Contains(lower, strings.ToLower(h.canonical)) {
			continue
		}
		if h.alt != "" && strings.Contains(lower, h.alt) {
			continue
		}
		emit(afind.New(h.rule,
			"Response configuration does not set "+h.label,
			h.severity, finding.ConfidenceLow).
			Path(f.Rel).Line(anchor).
			Evidence("missing_header", h.canonical).
			Desc("This file configures HTTP responses but does not set " + h.canonical + ".").
			Fix("Add " + h.canonical + " to the response headers for served content.").Done())
	}
}

// firstDirectiveLine returns the 1-based line of the first header directive and
// whether any was found. Falls back to line 1.
func firstDirectiveLine(content []byte, lower string) (int, bool) {
	for i, line := range strings.Split(lower, "\n") {
		for _, m := range directiveMarkers {
			if strings.Contains(line, m) {
				return i + 1, true
			}
		}
	}
	return 1, false
}
