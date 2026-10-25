// Command sentinel is the SentinelTriage CLI.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/codext4fn-afk/sentineltriage/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// After the first signal, restore default handling so a second Ctrl+C
	// terminates immediately even if report flushing is wedged on slow I/O.
	go func() {
		<-ctx.Done()
		stop()
	}()
	code := cli.New(os.Stdout, os.Stderr).Run(ctx, os.Args[1:])
	stop()
	os.Exit(int(code))
}
