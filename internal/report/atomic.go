// Package report holds output plumbing shared by every report format.
package report

import (
	"bufio"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// FileMode is applied to every report. Reports quote file paths, process
// command lines, and redacted credential prefixes; they are sensitive
// artifacts and default to owner-only access.
const FileMode fs.FileMode = 0o600

// EnsureDir creates dir with owner-only permissions if it does not exist.
func EnsureDir(dir string) error { return os.MkdirAll(dir, 0o700) }

// WriteAtomic writes path via a temporary file in the same directory followed
// by a rename, so a CI upload step or a second Ctrl+C never observes a
// truncated SARIF or JSON file. The temp file lives beside the target because
// rename is only atomic within one filesystem.
func WriteAtomic(path string, perm fs.FileMode, write func(io.Writer) error) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(name)
		}
	}()

	bw := bufio.NewWriterSize(tmp, 64<<10)
	if err = write(bw); err != nil {
		return err
	}
	if err = bw.Flush(); err != nil {
		return err
	}
	// Without fsync, a crash after rename can leave a zero-length file on
	// ext4 with delayed allocation.
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	// NOTE: on Windows Chmod only toggles the read-only attribute; ACLs are
	// inherited from the output directory.
	if err = os.Chmod(name, perm); err != nil {
		return err
	}
	return os.Rename(name, path)
}
