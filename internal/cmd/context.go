package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
)

// NewSignalContext creates a context that is cancelled when SIGINT or SIGTERM
// is received. The returned cancel function should be called to release resources.
func NewSignalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// handleScanError prints a cancellation message if the error indicates cancellation
// and returns a wrapped scan error. The ctx parameter is accepted for API consistency
// and future extensibility (e.g., logging or metrics).
func handleScanError(ctx context.Context, err error) error {
	_ = ctx // unused but kept for API consistency
	if errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "") // newline before warning
		cli.PrintWarning("Scan cancelled")
	}
	return fmt.Errorf("scan failed: %w", err)
}
