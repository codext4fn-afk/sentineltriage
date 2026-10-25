//go:build linux

package persistence

import "os"

// New returns a collector rooted at the live filesystem. os.DirFS is confined
// to the given root, so glob and open cannot traverse above "/".
func New() *Collector { return FromFS(os.DirFS("/")) }
