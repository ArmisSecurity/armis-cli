package cmd

import (
	"github.com/ArmisSecurity/armis-cli/internal/supplychain"
	"github.com/spf13/cobra"
)

// loadConfigUpward searches from dir upward (via FindConfigDir) for a
// .armis-supply-chain.yaml and loads it. It returns the parsed config (nil if
// none is found), the directory the config was found in, and any load error.
// This keeps `check`, `status`, and `wrap` consistent: a config in a parent
// directory applies when commands are run from a subdirectory.
func loadConfigUpward(dir string) (*supplychain.Config, string, error) {
	configDir := supplychain.FindConfigDir(dir)
	if configDir == "" {
		return nil, "", nil
	}
	cfg, err := supplychain.LoadConfig(configDir)
	if err != nil {
		return nil, configDir, err
	}
	return cfg, configDir, nil
}

var supplyChainCmd = &cobra.Command{
	Use:   "supply-chain",
	Short: "Enforce package release age policies",
	Long: `Protect your supply chain by enforcing minimum release age policies on packages.

The supply-chain command family audits lockfiles in CI and enforces policies locally
during package installations. Packages published too recently (e.g., within 72 hours)
are flagged or blocked to prevent supply chain attacks via typosquatting,
compromised maintainer accounts, or dependency confusion.

Supported ecosystems:
  Node:   npm, pnpm, bun, yarn (transparent proxy enforcement)
  Python: pip, uv (transparent proxy); poetry, pipenv, pdm (pre-install block)
  Java:   maven (pom.xml), gradle (gradle.lockfile) (pre-install block)

No Armis Cloud authentication is required — supply-chain queries public registries
(npm registry, PyPI, Maven Central).`,
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
