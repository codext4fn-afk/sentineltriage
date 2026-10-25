package ui

import (
	"os"
	"strconv"

	"golang.org/x/term"
)

// TermSize returns the terminal dimensions of f. When f is not a terminal it
// falls back to $COLUMNS and a fixed width, so redirected output and CI logs
// still get a stable layout.
func TermSize(f *os.File) (w, h int) {
	if f != nil {
		if w, h, err := term.GetSize(int(f.Fd())); err == nil && w > 0 {
			return w, h
		}
	}
	if c, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && c > 0 {
		return c, 0
	}
	return 120, 0
}

// EnableANSI prepares f to interpret ANSI escape sequences and reports whether
// it can. It is a no-op on Unix terminals; on Windows it switches the console
// into virtual-terminal mode, which conhost does not enable by default.
func EnableANSI(f *os.File) bool { return enableVT(f) }
