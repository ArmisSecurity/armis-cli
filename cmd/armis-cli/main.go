// Package main is the entry point for the Armis CLI.
package main

import (
	"errors"
	"os"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/cmd"
	"github.com/ArmisSecurity/armis-cli/internal/output"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cmd.SetVersion(version, commit, date)
	// Initialize colors early with auto-detection as fallback.
	// This handles cases where PersistentPreRunE doesn't fire (e.g., flag parsing errors).
	// The actual --color flag value will override this in PersistentPreRunE.
	cli.InitColors(cli.ColorModeAuto)

	err := cmd.Execute()

	if err != nil {
		// Handle findings exceeded threshold (not an error, just exit code signaling to CI)
		var findingsErr *output.ErrFindingsExceeded
		if errors.As(err, &findingsErr) {
			cmd.PrintUpdateNotification()
			os.Exit(findingsErr.ExitCode)
		}
		// Handle user cancellation (Ctrl+C) cleanly without printing error
		if errors.Is(err, cmd.ErrScanCancelled) {
			cmd.PrintUpdateNotification()
			os.Exit(cmd.ExitCodeCancelled)
		}
		cli.PrintError(err.Error())
		cmd.PrintUpdateNotification()
		os.Exit(1)
	}

	// Success path: print update notification at the very end (matches gh CLI pattern)
	cmd.PrintUpdateNotification()
}
