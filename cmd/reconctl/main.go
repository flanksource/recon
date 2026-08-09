// Command reconctl maintains an attack-surface inventory, keeps it current with
// pluggable discovery engines, and scans a filtered selection of it.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/flanksource/recon/internal/cli"
)

func main() {
	// Cancel on the first signal; a second one kills. Long-running commands
	// supervise child processes, and they need the chance to tear down their
	// process groups rather than orphaning a running scanner.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := cli.New().ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
