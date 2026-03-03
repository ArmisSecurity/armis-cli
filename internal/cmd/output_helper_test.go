package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/spf13/cobra"
)

// Output helper test format constants to satisfy goconst linter
const (
	ohFormatHuman = "human"
	ohFormatJSON  = "json"
	ohFormatSARIF = "sarif"
	ohFormatJUnit = "junit"
)

func TestResolveOutput(t *testing.T) {
	// Helper to create a minimal cobra command with format flag
	newTestCmd := func() *cobra.Command {
		cmd := &cobra.Command{Use: "test"}
		cmd.Flags().String("format", ohFormatHuman, "output format")
		return cmd
	}

	t.Run("returns stdout when no output path", func(t *testing.T) {
		cmd := newTestCmd()
		cfg, err := ResolveOutput(cmd, "", ohFormatHuman, "auto")
		if err != nil {
			t.Fatalf("ResolveOutput() error = %v", err)
		}
		defer cfg.cleanup()

		if cfg.Writer != os.Stdout {
			t.Error("expected Writer to be os.Stdout when outputPath is empty")
		}
		if cfg.Format != ohFormatHuman {
			t.Errorf("expected Format = %q, got %q", ohFormatHuman, cfg.Format)
		}
	})

	t.Run("auto-detects JSON format from extension", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, "results.json")

		cmd := newTestCmd()
		// Don't mark format as changed - let auto-detection kick in
		cfg, err := ResolveOutput(cmd, outputPath, ohFormatHuman, "auto")
		if err != nil {
			t.Fatalf("ResolveOutput() error = %v", err)
		}
		defer cfg.cleanup()

		if cfg.Format != ohFormatJSON {
			t.Errorf("expected Format = %q (auto-detected), got %q", ohFormatJSON, cfg.Format)
		}
	})

	t.Run("auto-detects SARIF format from extension", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, "results.sarif")

		cmd := newTestCmd()
		cfg, err := ResolveOutput(cmd, outputPath, ohFormatHuman, "auto")
		if err != nil {
			t.Fatalf("ResolveOutput() error = %v", err)
		}
		defer cfg.cleanup()

		if cfg.Format != ohFormatSARIF {
			t.Errorf("expected Format = %q (auto-detected), got %q", ohFormatSARIF, cfg.Format)
		}
	})

	t.Run("auto-detects JUnit format from .xml extension", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, "results.xml")

		cmd := newTestCmd()
		cfg, err := ResolveOutput(cmd, outputPath, ohFormatHuman, "auto")
		if err != nil {
			t.Fatalf("ResolveOutput() error = %v", err)
		}
		defer cfg.cleanup()

		if cfg.Format != ohFormatJUnit {
			t.Errorf("expected Format = %q (auto-detected), got %q", ohFormatJUnit, cfg.Format)
		}
	})

	t.Run("explicit format flag overrides auto-detection", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, "results.json")

		cmd := newTestCmd()
		// Simulate user explicitly setting --format=sarif
		if err := cmd.Flags().Set("format", ohFormatSARIF); err != nil {
			t.Fatalf("failed to set flag: %v", err)
		}

		cfg, err := ResolveOutput(cmd, outputPath, ohFormatSARIF, "auto")
		if err != nil {
			t.Fatalf("ResolveOutput() error = %v", err)
		}
		defer cfg.cleanup()

		if cfg.Format != ohFormatSARIF {
			t.Errorf("expected Format = %q (explicit), got %q", ohFormatSARIF, cfg.Format)
		}
	})

	t.Run("creates output file", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, "output.txt")

		cmd := newTestCmd()
		cfg, err := ResolveOutput(cmd, outputPath, ohFormatHuman, "auto")
		if err != nil {
			t.Fatalf("ResolveOutput() error = %v", err)
		}
		defer cfg.cleanup()

		// Verify file was created
		if _, err := os.Stat(outputPath); os.IsNotExist(err) {
			t.Error("expected output file to be created")
		}

		// Verify we can write to it
		_, err = cfg.Writer.Write([]byte("test content"))
		if err != nil {
			t.Errorf("Write() error = %v", err)
		}
	})

	t.Run("creates parent directories", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, "nested", "dir", "output.txt")

		cmd := newTestCmd()
		cfg, err := ResolveOutput(cmd, outputPath, ohFormatHuman, "auto")
		if err != nil {
			t.Fatalf("ResolveOutput() error = %v", err)
		}
		defer cfg.cleanup()

		// Verify nested directories and file were created
		if _, err := os.Stat(outputPath); os.IsNotExist(err) {
			t.Error("expected output file with nested directories to be created")
		}
	})

	t.Run("cleanup resets outputToFile state", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, "output.txt")

		cmd := newTestCmd()
		cfg, err := ResolveOutput(cmd, outputPath, ohFormatHuman, "auto")
		if err != nil {
			t.Fatalf("ResolveOutput() error = %v", err)
		}

		// Call cleanup
		cfg.cleanup()

		// Verify state was reset by checking colors work in auto mode
		// (outputToFile=false means colors depend on TTY, not forced off)
		cli.InitColors(cli.ColorModeAlways)
		if !cli.ColorsEnabled() {
			t.Error("expected colors to be enabled after cleanup reset state")
		}
	})

	t.Run("color=always skips color disabling", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, "output.txt")

		cmd := newTestCmd()
		cfg, err := ResolveOutput(cmd, outputPath, ohFormatHuman, "always")
		if err != nil {
			t.Fatalf("ResolveOutput() error = %v", err)
		}
		defer cfg.cleanup()

		// With --color=always, colors should remain enabled even when writing to file
		cli.InitColors(cli.ColorModeAlways)
		if !cli.ColorsEnabled() {
			t.Error("expected colors to remain enabled with --color=always")
		}
	})

	t.Run("returns error for invalid path", func(t *testing.T) {
		// Try to create file in non-existent root directory
		outputPath := "/nonexistent_root_xyz/output.txt"

		cmd := newTestCmd()
		_, err := ResolveOutput(cmd, outputPath, ohFormatHuman, "auto")
		if err == nil {
			t.Error("expected error for invalid path")
		}
	})

	t.Run("resets state on error", func(t *testing.T) {
		// Ensure outputToFile is reset even when file creation fails
		outputPath := "/nonexistent_root_xyz/output.txt"

		cmd := newTestCmd()
		_, _ = ResolveOutput(cmd, outputPath, ohFormatHuman, "auto")

		// Verify state was reset by checking colors work
		cli.InitColors(cli.ColorModeAlways)
		if !cli.ColorsEnabled() {
			t.Error("expected outputToFile state to be reset after error")
		}
	})

	t.Run("unrecognized extension keeps original format", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, "results.txt")

		cmd := newTestCmd()
		cfg, err := ResolveOutput(cmd, outputPath, ohFormatHuman, "auto")
		if err != nil {
			t.Fatalf("ResolveOutput() error = %v", err)
		}
		defer cfg.cleanup()

		// .txt is not recognized, so format should stay as ohFormatHuman
		if cfg.Format != ohFormatHuman {
			t.Errorf("expected Format = %q (unrecognized extension), got %q", ohFormatHuman, cfg.Format)
		}
	})
}
