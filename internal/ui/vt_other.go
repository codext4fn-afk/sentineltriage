//go:build !windows

package ui

import "os"

func enableVT(*os.File) bool { return true }
