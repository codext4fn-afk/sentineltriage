//go:build !linux

package persistence

// New returns a collector that reports an unsupported-platform coverage gap.
// The persistence mechanisms audited here (ld.so.preload, cron, systemd) are
// Linux-specific; other platforms get an explicit gap rather than silence.
//
// TODO(roadmap): Windows persistence (Run keys, services, scheduled tasks) and
// macOS (launchd plists) warrant their own collectors mapped to the matching
// ATT&CK techniques.
func New() *Collector { return Unsupported() }
