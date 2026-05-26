package cmd

import (
	"github.com/spf13/cobra"
)

var protectCmd = &cobra.Command{
	Use:   "protect",
	Short: "Enforce package release age policies",
	Long: `Protect your supply chain by enforcing minimum release age policies on packages.

The protect command family audits lockfiles in CI and enforces policies locally
during package installations. Packages published too recently (e.g., within 72 hours)
are flagged or blocked to prevent supply chain attacks via typosquatting,
compromised maintainer accounts, or dependency confusion.

No Armis Cloud authentication is required — protect queries the public npm registry.`,
	Example: `  # Audit lockfile for recently-published packages (CI mode)
  armis-cli protect check

  # Audit with custom age threshold
  armis-cli protect check --min-age 7d

  # Set up local enforcement
  armis-cli protect init

  # Check what protect init would do
  armis-cli protect init --dry-run`,
}

func init() {
	if rootCmd != nil {
		rootCmd.AddCommand(protectCmd)
	}
}
