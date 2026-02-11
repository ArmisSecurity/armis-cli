// Package main is the entry point for the Armis CLI.
package main

import (
	"os"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/cmd"
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
	if err := cmd.Execute(); err != nil {
		cli.PrintError(err.Error())
		os.Exit(1)
	}
}
