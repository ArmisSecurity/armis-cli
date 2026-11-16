// Package cmdutil holds command plumbing shared across the cmd package and its
// subpackages (e.g. supplychain). It exists to break what would otherwise be an
// import cycle: cmd imports its command subpackages to wire them into the root
// command, so those subpackages cannot import cmd back. Helpers both sides need
// live here, the one package both can import.
package cmdutil

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
// Called via defer in scan commands; the defer ensures cleanup on all exit paths.
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
//	cfg, err := cmdutil.ResolveOutput(cmd, outputFile, format, colorFlag)
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

	cfg.Format = EffectiveFormat(cmd, outputPath, formatFlag)

	// Capture previous state for restoration on error or cleanup
	prevOutputToFile := cli.GetOutputToFile()
	colorMode := cli.ColorMode(colorFlag)

	// Disable colors when writing to file (unless --color=always)
	if colorMode != cli.ColorModeAlways {
		cli.SetOutputToFile(true)
		cli.InitColors(colorMode) // Pass actual mode, not hardcoded Auto
		output.SyncColors()
	}

	// armis:ignore cwe:22 reason:outputPath is from --output flag; user-controlled CLI arg for their own files
	fileOutput, err := output.NewFileOutput(outputPath) // armis:ignore cwe:73 reason:outputPath from --output flag; user's own files
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

// EffectiveFormat is the format a command writes its results in: --format
// when it was set explicitly, otherwise the format implied by the --output
// file's extension, otherwise formatFlag's default. ResolveOutput and the
// `scan --async` record share it, so both judge a format the same way.
func EffectiveFormat(cmd *cobra.Command, outputPath, formatFlag string) string {
	// cmd.Flag() rather than cmd.Flags().Changed(): --format is inherited from
	// an ancestor command, and Flags() does not include inherited flags.
	if f := cmd.Flag("format"); f != nil && f.Changed {
		return formatFlag
	}
	if detected := output.FormatFromExtension(outputPath); detected != "" {
		return detected
	}
	return formatFlag
}
