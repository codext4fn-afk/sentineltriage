package audit

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/codext4fn-afk/sentineltriage/internal/audit/walker"
	"github.com/codext4fn-afk/sentineltriage/internal/engine"
	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

// capturingSink is a concurrency-safe engine.Sink for exercising the collector
// outside the full engine.
type capturingSink struct {
	mu       sync.Mutex
	findings []finding.Finding
	degrades []engine.Degradation
}

func (s *capturingSink) Emit(f finding.Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.findings = append(s.findings, f)
}
func (s *capturingSink) Degrade(d engine.Degradation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.degrades = append(s.degrades, d)
}

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestCollectorEndToEnd(t *testing.T) {
	root := writeTree(t, map[string]string{
		"Dockerfile":    "FROM alpine:latest\n",
		"deploy/p.yaml": "kind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n    - name: c\n      image: x\n      securityContext:\n        privileged: true\n",
		"README.md":     "# docs\n",
	})
	s := &capturingSink{}
	c := New(Config{Roots: []string{root}})
	if err := c.Run(context.Background(), s); err != nil {
		t.Fatalf("Run: %v", err)
	}
	seen := map[string]bool{}
	for _, f := range s.findings {
		seen[f.RuleID] = true
		if f.Engine != "" {
			t.Error("collector must not stamp Engine; the sink owns identity")
		}
	}
	if !seen["drift.dockerfile.unpinned-base"] || !seen["drift.k8s.privileged"] {
		t.Errorf("expected cross-analyzer findings, got %v", seen)
	}
}

func TestCollectorParallelEmitIsRaceFree(t *testing.T) {
	files := map[string]string{}
	for i := range 200 {
		files[filepath.Join("d", "f"+itoa(i)+".yaml")] = "kind: Pod\nspec:\n  containers:\n    - name: c\n      image: x\n      securityContext:\n        privileged: true\n"
	}
	root := writeTree(t, files)
	s := &capturingSink{}
	c := New(Config{Roots: []string{root}, Workers: 8})
	if err := c.Run(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	// Each manifest yields privileged + run-as-root + privilege-escalation = 3.
	if len(s.findings) != 600 {
		t.Errorf("findings = %d, want 600 (run with -race to catch sink races)", len(s.findings))
	}
}

func TestCollectorCancellation(t *testing.T) {
	files := map[string]string{}
	for i := range 50 {
		files["f"+itoa(i)+".yaml"] = "kind: Pod\n"
	}
	root := writeTree(t, files)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := New(Config{Roots: []string{root}})
	if err := c.Run(ctx, &capturingSink{}); err == nil {
		t.Error("cancelled Run returned nil")
	}
}

func TestCollectorInterfaceConformance(t *testing.T) {
	var _ engine.Collector = New(Config{Roots: []string{"."}})
	if c := New(Config{Roots: []string{"."}}); c.Name() != "audit.files" || c.Engine() != finding.EngineAudit {
		t.Errorf("identity = %s/%s", c.Name(), c.Engine())
	}
}

func TestCollectorAppliesPrefilter(t *testing.T) {
	// A stub analyzer records which files reach Analyze; README.md applies to
	// none and must be filtered before Analyze.
	stub := &recordingAnalyzer{}
	root := writeTree(t, map[string]string{"Dockerfile": "FROM x\n", "README.md": "hi\n"})
	c := New(Config{Roots: []string{root}, Analyzers: []Analyzer{stub}})
	_ = c.Run(context.Background(), &capturingSink{})
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if len(stub.seen) != 1 || stub.seen[0] != "Dockerfile" {
		t.Errorf("Analyze reached %v, want only Dockerfile", stub.seen)
	}
}

type recordingAnalyzer struct {
	mu   sync.Mutex
	seen []string
}

func (*recordingAnalyzer) Name() string { return "stub" }
func (*recordingAnalyzer) Applies(rel string) bool {
	return filepath.Base(rel) == "Dockerfile"
}
func (r *recordingAnalyzer) Analyze(f walker.File, _ func(finding.Finding)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, f.Rel)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
