package cli

import (
	"os"

	"golang.org/x/term"
)

// IsInteractive returns true if stdin and stderr are attached to a terminal.
// Both are needed for TUI flows — stdin for input, stderr for rendering.
func IsInteractive() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && //nolint:gosec // G115: fd conversion is safe
		term.IsTerminal(int(os.Stderr.Fd())) //nolint:gosec // G115: fd conversion is safe
}
