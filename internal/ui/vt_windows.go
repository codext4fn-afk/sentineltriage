//go:build windows

package ui

import (
	"os"

	"golang.org/x/sys/windows"
)

func enableVT(f *os.File) bool {
	if f == nil {
		return false
	}
	h := windows.Handle(f.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return false
	}
	if mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
		return true
	}
	// Fails on pre-1607 Windows 10 consoles, which then get uncolored output.
	return windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) == nil
}
