package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// NewSignalContext creates a context that is cancelled when SIGINT or SIGTERM
// is received. The returned cancel function should be called to release resources.
func NewSignalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// handleScanError prints a cancellation message if the context was cancelled
// and returns a wrapped scan error.
func handleScanError(ctx context.Context, err error) error {
	if ctx.Err() == context.Canceled {
		fmt.Fprintln(os.Stderr, "\nScan cancelled")
	}
	return fmt.Errorf("scan failed: %w", err)
}
