// Package walker enumerates audit targets under one or more roots. It is the
// single choke point for the resource and safety limits the audit engine
// depends on: file size caps, binary exclusion, and refusal to follow symlinks
// out of the scanned tree.
package walker

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Default limits.
const (
	// DefaultMaxFileBytes bounds the content held for any one file. Config
	// files worth auditing are small; the cap stops a multi-gigabyte log from
	// pinning a worker's memory.
	DefaultMaxFileBytes int64 = 2 << 20
	// sniffBytes is how much of a file is inspected for a NUL byte before it
	// is classified as binary and skipped.
	sniffBytes = 8 << 10
)

// File is one text file selected for analysis. Content is already bounded by
// the walker's size cap, so analyzers may hold it without further guarding.
type File struct {
	// Rel is slash-separated and relative to the root it was found under, so
	// that SARIF locations and fingerprints are stable across checkout dirs.
	Rel string
	// Abs is the on-disk path for diagnostics only.
	Abs  string
	Size int64
	// Truncated is set when the file exceeded the size cap and Content holds
	// only the first MaxFileBytes.
	Truncated bool
	Content   []byte
}

// Skip records a path that was not analyzed and why, so coverage stays honest.
type Skip struct {
	Rel    string
	Reason string
}

// Options configures a Walker. The zero value, after Walk applies defaults, is
// usable but scans nothing until Roots is set.
type Options struct {
	Roots        []string
	MaxFileBytes int64
	// Exclude holds path globs matched against each entry's slash path
	// relative to its root (e.g. "node_modules", "**/*.min.js"). Matching
	// directories are pruned, which is what keeps vendor trees cheap.
	Exclude []string
}

// defaultExcludes are pruned even when Options.Exclude is empty: these trees
// are large, machine-generated, and never the source of a config-drift finding.
var defaultExcludes = []string{
	".git", ".hg", ".svn", "node_modules", "vendor", ".terraform",
	"dist", "build", "target", ".venv", "venv", "__pycache__",
}

// Result reports what a walk covered.
type Result struct {
	Skipped []Skip
}

// Walk invokes fn for every selected file under the configured roots. fn is
// called from Walk's own goroutine, serially; the audit engine's parallelism
// lives above this layer so that the walk itself stays allocation-light and
// its traversal order deterministic.
//
// Walk returns ctx.Err() if cancelled mid-traversal. An unreadable file or
// directory is recorded as a Skip rather than aborting the walk: a single
// permission-denied path must not blind the whole audit.
func Walk(ctx context.Context, opts Options, fn func(File) error) (*Result, error) {
	if opts.MaxFileBytes <= 0 {
		opts.MaxFileBytes = DefaultMaxFileBytes
	}
	excludes := append(append([]string{}, defaultExcludes...), opts.Exclude...)
	res := &Result{}

	for _, root := range opts.Roots {
		root = filepath.Clean(root)
		walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			rel := relSlash(root, p)
			if err != nil {
				res.Skipped = append(res.Skipped, Skip{Rel: rel, Reason: "read error: " + err.Error()})
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if excluded(rel, d.IsDir(), excludes) {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			// Symlinks are never followed: a link under the scanned tree could
			// point at /etc or a sibling repo and smuggle its contents into
			// this report, or form a traversal cycle. WalkDir does not descend
			// into them, but a symlinked regular file would still be opened, so
			// it is skipped explicitly.
			if d.Type()&fs.ModeSymlink != 0 {
				res.Skipped = append(res.Skipped, Skip{Rel: rel, Reason: "symlink"})
				return nil
			}
			if d.IsDir() || !d.Type().IsRegular() {
				return nil
			}
			f, skip, readErr := read(p, rel, opts.MaxFileBytes)
			switch {
			case readErr != nil:
				res.Skipped = append(res.Skipped, Skip{Rel: rel, Reason: readErr.Error()})
				return nil
			case skip != nil:
				res.Skipped = append(res.Skipped, *skip)
				return nil
			}
			return fn(f)
		})
		if walkErr != nil {
			return res, walkErr
		}
	}
	return res, nil
}

func read(abs, rel string, max int64) (File, *Skip, error) {
	fh, err := os.Open(abs)
	if err != nil {
		return File{}, &Skip{Rel: rel, Reason: "open: " + err.Error()}, nil
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil {
		return File{}, &Skip{Rel: rel, Reason: "stat: " + err.Error()}, nil
	}
	// Re-check regularity on the open handle: the dir entry may be stale, and
	// a device or FIFO would otherwise block the read forever.
	if !st.Mode().IsRegular() {
		return File{}, &Skip{Rel: rel, Reason: "not a regular file"}, nil
	}

	// One extra byte is read past the cap purely to detect truncation.
	buf, err := io.ReadAll(io.LimitReader(fh, max+1))
	if err != nil {
		return File{}, &Skip{Rel: rel, Reason: "read: " + err.Error()}, nil
	}
	truncated := int64(len(buf)) > max
	if truncated {
		buf = buf[:max]
	}
	sniff := buf
	if len(sniff) > sniffBytes {
		sniff = sniff[:sniffBytes]
	}
	if bytes.IndexByte(sniff, 0) >= 0 {
		return File{}, &Skip{Rel: rel, Reason: "binary"}, nil
	}
	return File{Rel: rel, Abs: abs, Size: st.Size(), Truncated: truncated, Content: buf}, nil, nil
}

func relSlash(root, p string) string {
	r, err := filepath.Rel(root, p)
	if err != nil {
		r = p
	}
	return filepath.ToSlash(r)
}

// excluded reports whether rel matches an exclude pattern. A bare name matches
// any path component (so "node_modules" prunes it at any depth); a pattern
// containing a slash is matched against the full relative path.
func excluded(rel string, isDir bool, patterns []string) bool {
	if rel == "." {
		return false
	}
	base := path.Base(rel)
	for _, pat := range patterns {
		// "**/" means "at any depth, including the root", which path.Match
		// cannot express on its own; match the remainder against the basename
		// as well as every path suffix.
		if rest, ok := strings.CutPrefix(pat, "**/"); ok {
			if m, _ := path.Match(rest, base); m {
				return true
			}
			if m, _ := path.Match(rest, rel); m {
				return true
			}
			continue
		}
		if strings.Contains(pat, "/") {
			if ok, _ := path.Match(pat, rel); ok {
				return true
			}
		} else if ok, _ := path.Match(pat, base); ok {
			return true
		}
	}
	return false
}
