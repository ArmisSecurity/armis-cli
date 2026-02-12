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

// ErrScanCancelled is a sentinel error indicating the scan was cancelled by the user.
// This is treated as a clean termination (warning is already printed, no additional
// error message needed) and should result in exit code 130 (128 + SIGINT).
var ErrScanCancelled = errors.New("scan cancelled by user")

// ExitCodeCancelled is the standard Unix exit code for SIGINT (128 + 2).
const ExitCodeCancelled = 130

// NewSignalContext creates a context that is cancelled when SIGINT or SIGTERM
// is received. The returned cancel function should be called to release resources.
func NewSignalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// handleScanError prints a cancellation message if the error indicates cancellation
// and returns an appropriate error. For context.Canceled, it prints a warning and
// returns ErrScanCancelled (which main.go handles specially without printing).
// For other errors, it returns a wrapped scan error.
// The ctx parameter is accepted for API consistency and future extensibility.
func handleScanError(ctx context.Context, err error) error {
	_ = ctx // unused but kept for API consistency
	if errors.Is(err, context.Canceled) {
		_, _ = fmt.Fprintln(os.Stderr, "") // newline before warning; ignore write errors
		cli.PrintWarning("Scan cancelled")
		return ErrScanCancelled
	}
	return fmt.Errorf("scan failed: %w", err)
}
