//go:build linux

package host

import (
	"github.com/codext4fn-afk/sentineltriage/internal/engine"
	"github.com/codext4fn-afk/sentineltriage/internal/host/linuxpersist"
)

func platformCollectors() []engine.Collector {
	return []engine.Collector{linuxpersist.New()}
}
