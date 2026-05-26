package cmd

import (
	"fmt"
	"os"

	"github.com/ArmisSecurity/armis-cli/internal/protect"
	"github.com/spf13/cobra"
)

var protectUninitCmd = &cobra.Command{
	Use:   "uninit",
	Short: "Remove local package age enforcement",
	Long: `Remove shell functions injected by 'armis-cli protect init'.

This scans your shell RC files (bashrc, zshrc, fish config) for armis-cli protect
blocks and removes them. Your package manager will return to its normal behavior.`,
	Example: `  # Remove all injected shell functions
  armis-cli protect uninit`,
	Args: cobra.NoArgs,
	RunE: runProtectUninit,
}

func init() {
	protectCmd.AddCommand(protectUninitCmd)
}

func runProtectUninit(_ *cobra.Command, _ []string) error {
	shells := protect.DetectShells()
	if len(shells) == 0 {
		fmt.Fprintf(os.Stderr, "No supported shells detected.\n")
		return nil
	}

	modified, err := protect.RemoveFunctions(shells)
	if err != nil {
		return err
	}

	if len(modified) == 0 {
		fmt.Fprintf(os.Stderr, "No armis-cli protect blocks found in shell RC files.\n")
		return nil
	}

	for _, f := range modified {
		fmt.Fprintf(os.Stderr, "  ✓ Cleaned: %s\n", f)
	}
	fmt.Fprintf(os.Stderr, "\nDone! Restart your shell or source the modified file(s).\n")
	return nil
}
