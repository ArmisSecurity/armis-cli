package cmd

import (
	"github.com/spf13/cobra"
)

var supplyChainCmd = &cobra.Command{
	Use:   "supply-chain",
	Short: "Enforce package release age policies",
	Long: `Protect your supply chain by enforcing minimum release age policies on packages.

The supply-chain command family audits lockfiles in CI and enforces policies locally
during package installations. Packages published too recently (e.g., within 72 hours)
are flagged or blocked to prevent supply chain attacks via typosquatting,
compromised maintainer accounts, or dependency confusion.

No Armis Cloud authentication is required — supply-chain queries the public npm registry.`,
	Example: `  # Audit lockfile for recently-published packages (CI mode)
  armis-cli supply-chain check

  # Audit with custom age threshold
  armis-cli supply-chain check --min-age 7d

  # Set up local enforcement
  armis-cli supply-chain init

  # Check what supply-chain init would do
  armis-cli supply-chain init --dry-run`,
}

func init() {
	if rootCmd != nil {
		rootCmd.AddCommand(supplyChainCmd)
	}
}
