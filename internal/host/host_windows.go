//go:build windows

package host

import (
	"github.com/codext4fn-afk/sentineltriage/internal/engine"
	"github.com/codext4fn-afk/sentineltriage/internal/host/winpersist"
)

func platformCollectors() []engine.Collector {
	return []engine.Collector{winpersist.New()}
}
