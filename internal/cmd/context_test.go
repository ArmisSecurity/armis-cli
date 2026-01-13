package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
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

func TestHandleScanError(t *testing.T) {
	// Helper to capture stderr output
	captureStderr := func(t *testing.T, f func()) string {
		t.Helper()
		oldStderr := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w

		f()

		if err := w.Close(); err != nil {
			t.Fatalf("failed to close pipe writer: %v", err)
		}
		os.Stderr = oldStderr

		var buf bytes.Buffer
		if _, err := io.Copy(&buf, r); err != nil {
			t.Fatalf("failed to copy stderr output: %v", err)
		}
		return buf.String()
	}

	t.Run("prints cancellation message when error contains context.Canceled", func(t *testing.T) {
		ctx := context.Background()
		cancelErr := fmt.Errorf("operation failed: %w", context.Canceled)

		var resultErr error
		output := captureStderr(t, func() {
			resultErr = handleScanError(ctx, cancelErr)
		})

		if !strings.Contains(output, "Scan cancelled") {
			t.Errorf("expected stderr to contain 'Scan cancelled', got: %q", output)
		}

		if !errors.Is(resultErr, context.Canceled) {
			t.Errorf("expected wrapped error to contain context.Canceled")
		}

		if !strings.Contains(resultErr.Error(), "scan failed") {
			t.Errorf("expected error message to contain 'scan failed', got: %q", resultErr.Error())
		}
	})

	t.Run("does not print cancellation message for non-cancellation errors", func(t *testing.T) {
		ctx := context.Background()
		otherErr := errors.New("network timeout")

		var resultErr error
		output := captureStderr(t, func() {
			resultErr = handleScanError(ctx, otherErr)
		})

		if strings.Contains(output, "Scan cancelled") {
			t.Errorf("expected stderr NOT to contain 'Scan cancelled' for non-cancellation error, got: %q", output)
		}

		if !strings.Contains(resultErr.Error(), "scan failed") {
			t.Errorf("expected error message to contain 'scan failed', got: %q", resultErr.Error())
		}

		if !strings.Contains(resultErr.Error(), "network timeout") {
			t.Errorf("expected wrapped error to contain original error message")
		}
	})

	t.Run("wraps error correctly", func(t *testing.T) {
		ctx := context.Background()
		originalErr := errors.New("original error")

		resultErr := handleScanError(ctx, originalErr)

		if !errors.Is(resultErr, originalErr) {
			t.Errorf("expected wrapped error to unwrap to original error")
		}
	})
}
