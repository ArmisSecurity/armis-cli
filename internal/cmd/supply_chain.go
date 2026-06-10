package cmd

import (
	"fmt"
	"os"
	"strings"

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
	if cfg != nil {
		// Surface typos in the config's "ecosystems" list once, here, so every
		// command that loads the config (check/status/wrap) reports them
		// consistently rather than silently ignoring an unrecognized name.
		if unknown := cfg.UnknownEcosystems(); len(unknown) > 0 {
			fmt.Fprintf(os.Stderr, "Warning: unknown ecosystem(s) %s in %s — supported: %s\n",
				strings.Join(unknown, ", "), supplychain.ConfigFileName, supplychain.KnownEcosystemsHint())
		}
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
  Node:   npm, npx, pnpm, bun, yarn (transparent proxy enforcement)
          npx enforces packages it fetches; a package already in the npx cache
          or a binary in node_modules/.bin runs without a registry round-trip.
  Python: pip, uv, uvx (transparent proxy); poetry, pipenv, pdm (pre-install block)
          uvx (uv's tool runner) enforces tools it fetches; a tool already in the
          uv tool cache runs without a registry round-trip.
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
	// A parent command with no RunE prints help and exits 0 on an unknown
	// subcommand, so `supply-chain chekc` silently "succeeds" in CI. Reject
	// unknown args with a non-zero exit and a "did you mean" suggestion; with no
	// args, fall back to the usual help text.
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return cmd.Help()
		}
		// SuggestionsMinimumDistance is 0 here because cobra only sets its default
		// (2) deeper in its own execute path, which we bypass by calling
		// SuggestionsFor directly. Set it so close typos like "chekc"→"check" are
		// offered.
		if cmd.SuggestionsMinimumDistance <= 0 {
			cmd.SuggestionsMinimumDistance = 2
		}
		err := fmt.Errorf("unknown subcommand %q for %q", args[0], cmd.CommandPath())
		if suggestions := cmd.SuggestionsFor(args[0]); len(suggestions) > 0 {
			err = fmt.Errorf("%w\n\nDid you mean this?\n\t%s", err, strings.Join(suggestions, "\n\t"))
		}
		return err
	},
}

func init() {
	if rootCmd != nil {
		rootCmd.AddCommand(supplyChainCmd)
	}
}
