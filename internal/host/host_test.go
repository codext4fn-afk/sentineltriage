package host

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/codext4fn-afk/sentineltriage/internal/engine"
	"github.com/codext4fn-afk/sentineltriage/internal/finding"
)

func TestCollectorsNonEmpty(t *testing.T) {
	cs, err := Collectors("")
	if err != nil || len(cs) == 0 {
		t.Fatalf("no host collectors for this platform: %v", err)
	}
	for _, c := range cs {
		if c.Engine() != "host" || c.Name() == "" {
			t.Errorf("bad identity %q/%q", c.Name(), c.Engine())
		}
	}
}

func TestOfflineRootUsesLinuxCollector(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "ld.so.preload"), []byte("/lib/x.so\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cs, err := Collectors(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 1 || cs[0].Name() != "host.persistence.linux" {
		t.Fatalf("offline collectors = %v", cs)
	}
	var s captureSink
	if err := cs[0].Run(context.Background(), &s); err != nil {
		t.Fatal(err)
	}
	if s.findings != 1 {
		t.Errorf("findings = %d, want 1 from the mounted image", s.findings)
	}
}

func TestOfflineRootMustExist(t *testing.T) {
	if _, err := Collectors(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("missing root accepted")
	}
}

func TestUnsupportedReportsGap(t *testing.T) {
	if err := (unsupported{}).Run(context.Background(), nil); !errors.Is(err, engine.ErrUnsupported) {
		t.Errorf("err = %v, want ErrUnsupported", err)
	}
}

type captureSink struct{ findings int }

func (c *captureSink) Emit(_ finding.Finding)       { c.findings++ }
func (c *captureSink) Degrade(_ engine.Degradation) {}
