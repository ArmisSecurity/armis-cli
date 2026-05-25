package cli

import (
	"os"

	"golang.org/x/term"
)

// IsInteractive returns true if stdin is attached to a terminal.
func IsInteractive() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) //nolint:gosec // G115: fd conversion is safe for stdin
}
