package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

func TestDefaultIsValid(t *testing.T) {
	c := Default()
	if err := c.Validate(); err != nil {
		t.Fatalf("default config invalid: %v", err)
	}
}

func TestLoadOverlaysDefaults(t *testing.T) {
	cfg, err := Load(strings.NewReader(`
version: 1
budget: 30s
fail_on: CRITICAL
engines:
  audit:
    paths: [src, infra]
`))
	if err != nil {
		t.Fatal(err)
	}
	if time.Duration(cfg.Budget) != 30*time.Second || cfg.FailOn != finding.SeverityCritical {
		t.Errorf("budget=%v fail_on=%v", time.Duration(cfg.Budget), cfg.FailOn)
	}
	if got := cfg.Engines.Audit.Paths; len(got) != 2 || got[1] != "infra" {
		t.Errorf("paths = %v", got)
	}
	if !cfg.Engines.Host.Enabled || cfg.Engines.Audit.MaxFileBytes != 2<<20 {
		t.Error("unspecified fields lost their defaults")
	}
}

func TestLoadRejects(t *testing.T) {
	cases := map[string]string{
		"unknown key":       "version: 1\nfail_onn: low\n",
		"wrong version":     "version: 2\n",
		"missing version":   "budget: 5s\n",
		"bare int duration": "version: 1\nbudget: 10\n",
		"bad duration":      "version: 1\nbudget: soon\n",
		"bad severity":      "version: 1\nfail_on: severe\n",
		"coverage range":    "version: 1\nmin_coverage: 1.5\n",
		"no engines":        "version: 1\nengines: {host: {enabled: false}, audit: {enabled: false}}\n",
		"unknown format":    "version: 1\noutput: {formats: [pdf]}\n",
		"multi document":    "version: 1\n---\nversion: 1\n",
		"empty":             "  \n",
	}
	for name, doc := range cases {
		if _, err := Load(strings.NewReader(doc)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestLoadSizeCap(t *testing.T) {
	doc := "version: 1\n# " + strings.Repeat("x", maxConfigBytes) + "\n"
	if _, err := Load(strings.NewReader(doc)); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("oversized config: err=%v", err)
	}
}

func TestLoadFileRejectsNonRegular(t *testing.T) {
	if _, err := LoadFile(t.TempDir()); err == nil {
		t.Error("directory accepted as config file")
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	c := Default()
	c.Budget = Duration(42 * time.Second)
	c.FailOn = finding.SeverityMedium
	b, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadFile(p)
	if err != nil {
		t.Fatalf("re-load of marshalled config failed: %v\n%s", err, b)
	}
	if got.Budget != c.Budget || got.FailOn != c.FailOn {
		t.Errorf("round trip mismatch: %+v", got)
	}
	if !bytes.Contains(b, []byte("budget: 42s")) {
		t.Errorf("duration not rendered as string:\n%s", b)
	}
}
