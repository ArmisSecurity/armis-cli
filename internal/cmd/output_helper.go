package cmd

import (
	"io"
	"os"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/spf13/cobra"
)

// OutputConfig holds the resolved output configuration for scan commands.
type OutputConfig struct {
	// Writer is the destination for formatted output (stdout or file).
	Writer io.Writer
	// Format is the resolved output format (may differ from flag if auto-detected).
	Format string
	// cleanup is called to close the file and reset state. Always call this via defer.
	cleanup func()
	// cleaned tracks whether cleanup has already been called (for idempotency)
	cleaned bool
}

// Cleanup closes the output file (if any) and restores color state.
// This method is idempotent and safe to call multiple times.
// Call explicitly before os.Exit paths (like ExitIfNeeded) since defers won't run.
func (c *OutputConfig) Cleanup() {
	if c.cleaned {
		return
	}
	c.cleaned = true
	c.cleanup()
}

// ResolveOutput determines the output writer and format for scan results.
// It handles:
//   - Auto-detecting format from file extension (if --format not explicitly set)
//   - Creating the output file (with proper directory creation)
//   - Disabling colors when writing to file (unless --color=always)
//
// The returned OutputConfig.cleanup function MUST be called via defer to:
//   - Close the output file (if writing to file)
//   - Reset the outputToFile state for proper cleanup
//
// Example usage:
//
//	cfg, err := ResolveOutput(cmd, outputFile, format, colorFlag)
//	if err != nil {
//	    return err
//	}
//	defer cfg.Cleanup()
//	// use cfg.Writer and cfg.Format
func ResolveOutput(cmd *cobra.Command, outputPath, formatFlag, colorFlag string) (*OutputConfig, error) {
	cfg := &OutputConfig{
		Writer:  os.Stdout,
		Format:  formatFlag,
		cleanup: func() {}, // no-op by default
	}

	if outputPath == "" {
		return cfg, nil
	}

	// Auto-detect format from extension if user hasn't explicitly set --format.
	// Use cmd.Flag() instead of cmd.Flags().Changed() because --format is a
	// persistent flag on the root command, and Flags() doesn't include inherited flags.
	fmtFlag := cmd.Flag("format")
	formatExplicitlySet := fmtFlag != nil && fmtFlag.Changed
	if !formatExplicitlySet {
		if detected := output.FormatFromExtension(outputPath); detected != "" {
			cfg.Format = detected
		}
	}

	// Capture previous state for restoration on error or cleanup
	prevOutputToFile := cli.GetOutputToFile()
	colorMode := cli.ColorMode(colorFlag)

	// Disable colors when writing to file (unless --color=always)
	if colorMode != cli.ColorModeAlways {
		cli.SetOutputToFile(true)
		cli.InitColors(colorMode) // Pass actual mode, not hardcoded Auto
		output.SyncColors()
	}

	// Create output file
	fileOutput, err := output.NewFileOutput(outputPath)
	if err != nil {
		// Restore previous state on error
		cli.SetOutputToFile(prevOutputToFile)
		cli.InitColors(colorMode)
		output.SyncColors()
		return nil, err
	}

	cfg.Writer = fileOutput.Writer()
	cfg.cleanup = func() {
		// Restore previous outputToFile state and re-sync colors
		cli.SetOutputToFile(prevOutputToFile)
		cli.InitColors(colorMode)
		output.SyncColors()
		if cerr := fileOutput.Close(); cerr != nil {
			cli.PrintWarningf("failed to close output file: %v", cerr)
		}
	}

	return cfg, nil
}
