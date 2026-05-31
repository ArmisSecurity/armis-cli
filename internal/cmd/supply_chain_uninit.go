package cmd

import (
	"fmt"
	"os"

	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/supplychain"
	"github.com/spf13/cobra"
)

var scUninitCmd = &cobra.Command{
	Use:   "uninit",
	Short: "Remove local package age enforcement",
	Long: `Remove shell functions injected by 'armis-cli supply-chain init'.

This scans your shell RC files (bashrc, zshrc, fish config) for armis-cli supply-chain
blocks and removes them. Your package manager will return to its normal behavior.`,
	Example: `  # Remove all injected shell functions
  armis-cli supply-chain uninit`,
	Args: cobra.NoArgs,
	RunE: runSupplyChainUninit,
}

func init() {
	supplyChainCmd.AddCommand(scUninitCmd)
}

func runSupplyChainUninit(_ *cobra.Command, _ []string) error {
	s := output.GetStyles()

	shells := supplychain.DetectShells()
	if len(shells) == 0 {
		fmt.Fprintf(os.Stderr, "%s\n", s.MutedText.Render("No supported shells detected."))
		return nil
	}

	modified, err := supplychain.RemoveFunctions(shells)
	if err != nil {
		return err
	}

	if len(modified) == 0 {
		fmt.Fprintf(os.Stderr, "%s\n", s.MutedText.Render("No armis-cli supply-chain blocks found in shell RC files."))
		return nil
	}

	for _, f := range modified {
		fmt.Fprintf(os.Stderr, "  %s Cleaned: %s\n", s.SuccessText.Render(output.IconSuccess), s.Bold.Render(f))
	}
	fmt.Fprintf(os.Stderr, "\n%s Restart your shell or source the modified file(s).\n", s.SuccessText.Render("Done!"))
	return nil
}
