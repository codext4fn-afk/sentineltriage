package headers

import (
	"slices"
	"testing"

	"github.com/codext4fn-afk/sentineltriage/internal/audit/walker"
	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

func run(rel, body string) []finding.Finding {
	a := Analyzer{}
	f := walker.File{Rel: rel, Content: []byte(body)}
	if !a.Applies(f) {
		return nil
	}
	var out []finding.Finding
	a.Analyze(f, func(x finding.Finding) { out = append(out, x) })
	return out
}

func rules(fs []finding.Finding) []string {
	var r []string
	for _, f := range fs {
		r = append(r, f.RuleID)
	}
	slices.Sort(r)
	return r
}

func TestNginxMissingHeaders(t *testing.T) {
	body := `server {
    add_header X-Content-Type-Options "nosniff";
    add_header Strict-Transport-Security "max-age=63072000";
}`
	got := rules(run("sites-available/site.conf", body))
	want := []string{"headers.missing-csp", "headers.missing-frame-options", "headers.missing-referrer-policy"}
	if !slices.Equal(got, want) {
		t.Errorf("rules = %v, want %v", got, want)
	}
}

func TestFrameAncestorsSatisfiesFrameOptions(t *testing.T) {
	body := `server {
    add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'none'";
    add_header Strict-Transport-Security "max-age=1";
    add_header X-Content-Type-Options nosniff;
    add_header Referrer-Policy no-referrer;
}`
	if fs := run("nginx.conf", body); len(fs) != 0 {
		t.Errorf("fully-set config flagged: %v", rules(fs))
	}
}

func TestPlainConfWithoutHeadersIsQuiet(t *testing.T) {
	// A .conf that configures no response headers must not be flagged, to
	// avoid false positives on unrelated config files.
	if fs := run("app.conf", "listen 8080;\nworker_processes auto;\n"); len(fs) != 0 {
		t.Errorf("non-header conf flagged: %v", rules(fs))
	}
}

func TestDedicatedHeadersFileAlwaysChecked(t *testing.T) {
	// A Netlify _headers file with no security headers should flag even though
	// it contains no add_header directive.
	body := "/*\n  Cache-Control: max-age=0\n"
	if fs := run("_headers", body); len(fs) < 4 {
		t.Errorf("dedicated _headers file not fully checked: %v", rules(fs))
	}
}

func TestVercelJSONDetected(t *testing.T) {
	body := `{"headers":[{"source":"/(.*)","headers":[{"key":"X-Frame-Options","value":"DENY"}]}]}`
	got := rules(run("vercel.json", body))
	if slices.Contains(got, "headers.missing-frame-options") {
		t.Error("X-Frame-Options present but flagged missing")
	}
	if !slices.Contains(got, "headers.missing-csp") {
		t.Error("missing CSP not detected in vercel.json")
	}
}
