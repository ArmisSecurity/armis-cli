package cmd

import (
	"context"
	"errors"
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

// handleScanError prints a cancellation message if the error indicates cancellation
// and returns a wrapped scan error.
func handleScanError(_ context.Context, err error) error {
	if errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "\nScan cancelled")
	}
	return fmt.Errorf("scan failed: %w", err)
}
