//go:build !unix

package scan

import (
	"os"
	"testing"
)

// openFIFO skips the test: FIFOs need a Unix system.
func openFIFO(t *testing.T, _ string) *os.File {
	t.Helper()
	t.Skip("FIFOs need a Unix system")
	return nil
}
