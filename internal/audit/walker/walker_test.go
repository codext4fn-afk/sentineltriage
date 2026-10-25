package walker

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

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

func collect(t *testing.T, opts Options) (map[string]File, *Result) {
	t.Helper()
	got := map[string]File{}
	res, err := Walk(context.Background(), opts, func(f File) error { got[f.Rel] = f; return nil })
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	return got, res
}

func TestWalkSelectsTextPrunesExcludes(t *testing.T) {
	root := writeTree(t, map[string]string{
		"Dockerfile":            "FROM alpine",
		"k8s/pod.yaml":          "kind: Pod",
		"node_modules/dep/x.js": "secret",
		"vendor/lib.go":         "package lib",
		"nested/.git/config":    "[core]",
		"src/app.go":            "package main",
		"build/out.txt":         "artifact",
	})
	got, _ := collect(t, Options{Roots: []string{root}})
	want := []string{"Dockerfile", "k8s/pod.yaml", "src/app.go"}
	var have []string
	for k := range got {
		have = append(have, k)
	}
	slices.Sort(have)
	if !slices.Equal(have, want) {
		t.Errorf("selected %v, want %v", have, want)
	}
}

func TestWalkCustomExcludeGlob(t *testing.T) {
	root := writeTree(t, map[string]string{
		"app.js":     "code",
		"app.min.js": "minified",
		"keep.txt":   "x",
	})
	got, res := collect(t, Options{Roots: []string{root}, Exclude: []string{"**/*.min.js"}})
	if _, ok := got["app.min.js"]; ok {
		t.Error("*.min.js not excluded")
	}
	if _, ok := got["app.js"]; !ok {
		t.Error("app.js wrongly excluded")
	}
	_ = res
}

func TestWalkBinaryAndSizeCap(t *testing.T) {
	root := writeTree(t, map[string]string{
		"text.conf": strings.Repeat("a", 100),
		"big.conf":  strings.Repeat("b", 500),
	})
	if err := os.WriteFile(filepath.Join(root, "image.bin"), []byte{'P', 'K', 0x00, 0x01, 'x'}, 0o644); err != nil {
		t.Fatal(err)
	}
	got, res := collect(t, Options{Roots: []string{root}, MaxFileBytes: 200})
	if _, ok := got["image.bin"]; ok {
		t.Error("binary file not skipped")
	}
	big := got["big.conf"]
	if !big.Truncated || len(big.Content) != 200 {
		t.Errorf("size cap not applied: truncated=%v len=%d", big.Truncated, len(big.Content))
	}
	if got["text.conf"].Truncated {
		t.Error("small file wrongly marked truncated")
	}
	reasons := map[string]bool{}
	for _, s := range res.Skipped {
		reasons[s.Reason] = true
	}
	if !reasons["binary"] {
		t.Errorf("binary skip not recorded: %+v", res.Skipped)
	}
}

func TestWalkDoesNotFollowSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privilege on Windows")
	}
	root := writeTree(t, map[string]string{"real/secret.conf": "data"})
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "target.conf"), []byte("external"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "target.conf"), filepath.Join(root, "link.conf")); err != nil {
		t.Fatal(err)
	}
	got, res := collect(t, Options{Roots: []string{root}})
	if _, ok := got["link.conf"]; ok {
		t.Error("symlink was followed; external content leaked into audit")
	}
	if !slices.ContainsFunc(res.Skipped, func(s Skip) bool { return s.Reason == "symlink" }) {
		t.Errorf("symlink skip not recorded: %+v", res.Skipped)
	}
}

func TestWalkCancellation(t *testing.T) {
	root := writeTree(t, map[string]string{"a.conf": "1", "b.conf": "2", "c.conf": "3"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Walk(ctx, Options{Roots: []string{root}}, func(File) error { return nil })
	if err == nil {
		t.Error("cancelled walk returned nil error")
	}
}

func TestWalkMissingRootRecorded(t *testing.T) {
	_, res := collect(t, Options{Roots: []string{filepath.Join(t.TempDir(), "absent")}})
	if len(res.Skipped) == 0 {
		t.Error("missing root produced no skip record")
	}
}
