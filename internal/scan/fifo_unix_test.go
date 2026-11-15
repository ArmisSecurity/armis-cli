//go:build unix

package scan

import (
	"os"
	"syscall"
	"testing"
)

// openFIFO makes a FIFO at path and opens it for reading without blocking, so
// a writer can open it at once. It skips the test where FIFOs cannot be made.
func openFIFO(t *testing.T, path string) *os.File {
	t.Helper()
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Skipf("cannot create a FIFO: %v", err)
	}
	r, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) //nolint:gosec // test path from t.TempDir()
	if err != nil {
		t.Fatalf("open FIFO: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}
