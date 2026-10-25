package report

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAtomicReplaces(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "r.json")
	for _, body := range []string{"first", "second"} {
		if err := WriteAtomic(p, FileMode, func(w io.Writer) error { _, err := io.WriteString(w, body); return err }); err != nil {
			t.Fatal(err)
		}
	}
	if b, _ := os.ReadFile(p); string(b) != "second" {
		t.Errorf("content = %q, want second", b)
	}
	assertNoTempFiles(t, dir)
}

func TestWriteAtomicFailureLeavesTargetUntouched(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "r.json")
	if err := os.WriteFile(p, []byte("previous"), 0o600); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("encoder failed")
	err := WriteAtomic(p, FileMode, func(w io.Writer) error {
		_, _ = io.WriteString(w, "half-writ")
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
	if b, _ := os.ReadFile(p); string(b) != "previous" {
		t.Errorf("target modified on failure: %q", b)
	}
	assertNoTempFiles(t, dir)
}

func TestWriteAtomicMissingDir(t *testing.T) {
	p := filepath.Join(t.TempDir(), "absent", "r.json")
	if err := WriteAtomic(p, FileMode, func(io.Writer) error { return nil }); err == nil {
		t.Error("expected error for missing directory")
	}
}

func assertNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != "r.json" {
			t.Errorf("leftover file %q", e.Name())
		}
	}
}
