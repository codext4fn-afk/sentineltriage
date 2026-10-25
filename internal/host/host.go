// Package host selects the host-triage collectors for the running OS. Each
// platform registers exactly one persistence collector; platforms without one
// get an explicit unsupported collector so the gap appears in reports.
package host

import (
	"context"
	"fmt"
	"os"

	"github.com/codext4fn-afk/sentineltriage/internal/engine"
	"github.com/codext4fn-afk/sentineltriage/internal/finding"
	"github.com/codext4fn-afk/sentineltriage/internal/host/linuxpersist"
)

// Collectors returns the host collectors for this platform. A non-empty root
// selects offline mode instead: the Linux collector runs against a mounted
// filesystem at root, regardless of the OS sentinel itself runs on.
func Collectors(root string) ([]engine.Collector, error) {
	if root == "" {
		return platformCollectors(), nil
	}
	st, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("host root: %w", err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("host root %s is not a directory", root)
	}
	return []engine.Collector{linuxpersist.FromFS(os.DirFS(root))}, nil
}

// unsupported reports an ErrUnsupported coverage gap.
type unsupported struct{}

func (unsupported) Name() string           { return "host.persistence" }
func (unsupported) Engine() finding.Engine { return finding.EngineHost }
func (unsupported) Run(context.Context, engine.Sink) error {
	return engine.ErrUnsupported
}
