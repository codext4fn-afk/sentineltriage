//go:build !linux && !windows

package host

import "github.com/codext4fn-afk/sentineltriage/internal/engine"

// TODO: macOS launchd (LaunchAgents/LaunchDaemons plists, T1543.001/T1543.004).
func platformCollectors() []engine.Collector {
	return []engine.Collector{unsupported{}}
}
