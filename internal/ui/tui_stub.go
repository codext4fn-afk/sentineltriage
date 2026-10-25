//go:build !tui

package ui

import "io"

// TUIAvailable reports whether the interactive Bubble Tea renderer is compiled
// in. The default build omits it so the standard binary carries no TUI
// dependencies; build with -tags tui to include the live view.
func TUIAvailable() bool { return false }

// NewTUIRenderer is a no-op in the default build. The CLI only calls it when
// TUIAvailable reports true, so this stub exists solely to satisfy the linker.
func NewTUIRenderer(io.Writer) Renderer { return &Plain{Progress: io.Discard, Out: io.Discard} }
