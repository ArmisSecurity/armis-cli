package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// NewSignalContext creates a context that is cancelled when SIGINT or SIGTERM
// is received. The returned cancel function should be called to release resources.
func NewSignalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}
