package cmd

import (
	"context"
	"testing"
)

func TestNewSignalContext(t *testing.T) {
	t.Run("returns valid cancellable context", func(t *testing.T) {
		ctx, cancel := NewSignalContext()
		defer cancel()

		if ctx == nil {
			t.Fatal("expected non-nil context")
		}

		// Verify context is cancellable
		cancel()
		select {
		case <-ctx.Done():
			// Expected - context was cancelled
		default:
			t.Fatal("expected context to be cancelled after cancel() call")
		}

		if ctx.Err() != context.Canceled {
			t.Errorf("expected context.Canceled error, got %v", ctx.Err())
		}
	})

	t.Run("context is not cancelled before cancel is called", func(t *testing.T) {
		ctx, cancel := NewSignalContext()
		defer cancel()

		select {
		case <-ctx.Done():
			t.Fatal("context should not be cancelled before cancel() is called")
		default:
			// Expected - context is still active
		}
	})
}
