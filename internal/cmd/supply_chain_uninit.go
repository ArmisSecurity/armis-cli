package cmd

import (
	"fmt"
	"os"

	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/supplychain"
	"github.com/spf13/cobra"
)

var (
	scUninitDryRun bool
	scUninitYes    bool
)

var scUninitCmd = &cobra.Command{
	Use:   "uninit",
	Short: "Remove shell wrapper functions injected by supply-chain init",
	Long: `Remove the changes made by 'armis-cli supply-chain init'.

This scans your shell RC files (bashrc, zshrc, fish config) for armis-cli supply-chain
blocks and removes them, and strips the marker comment from a project .npmrc in the
current directory if present. Your package manager will return to its normal behavior.

The --mode config policy file (.armis-supply-chain.yaml) is meant to be committed, so it
is left in place; remove it manually if you no longer want it.`,
	Example: `  # Remove all injected shell functions
  armis-cli supply-chain uninit

  # Preview what would be removed without making changes
  armis-cli supply-chain uninit --dry-run

  # Non-interactive (CI friendly)
  armis-cli supply-chain uninit --yes`,
	Args: cobra.NoArgs,
	RunE: runSupplyChainUninit,
}

func init() {
	scUninitCmd.Flags().BoolVar(&scUninitDryRun, "dry-run", false, "Show what would be removed without making changes")
	scUninitCmd.Flags().BoolVar(&scUninitYes, "yes", false, "Skip confirmation prompt")
	supplyChainCmd.AddCommand(scUninitCmd)
}

func runSupplyChainUninit(_ *cobra.Command, _ []string) error {
	s := output.GetStyles()

	shells := supplychain.DetectShells()

	// Gather every artifact uninit would remove before touching anything: the
	// shell RC files that actually carry an injection block, and the project
	// .npmrc if it carries the marker comment. Computing the target set up front
	// powers the --dry-run preview and lets uninit report "nothing to do" without
	// writing. .npmrc is handled independently of shells: a user who only ran
	// `init --mode npmrc` has a marker to clean even with no wrappers installed.
	var rcTargets []string
	for _, sh := range shells {
		if supplychain.HasInjection(sh.RCFile) {
			rcTargets = append(rcTargets, sh.RCFile)
		}
	}
	npmrcTarget := supplychain.NpmrcFileHasMarker(supplychain.NpmrcFileName)

	if len(rcTargets) == 0 && !npmrcTarget {
		fmt.Fprintf(os.Stderr, "%s\n", s.MutedText.Render("No armis-cli supply-chain changes found in shell RC files or .npmrc."))
		return nil
	}

	// Preview the targets. Shown for --dry-run and also ahead of the interactive
	// confirm so the user sees exactly which files will change before consenting.
	fmt.Fprintf(os.Stderr, "%s\n", s.SectionTitle.Render("Will remove armis-cli supply-chain changes from:"))
	for _, f := range rcTargets {
		fmt.Fprintf(os.Stderr, "  %s\n", s.Bold.Render(f))
	}
	if npmrcTarget {
		fmt.Fprintf(os.Stderr, "  %s %s\n", s.Bold.Render(supplychain.NpmrcFileName), s.MutedText.Render("(marker comment)"))
	}

	if scUninitDryRun {
		fmt.Fprintf(os.Stderr, "%s\n", s.MutedText.Render("(dry-run: no changes made)"))
		return nil
	}

	if !scUninitYes {
		if !promptYesNo("Proceed?", true) {
			fmt.Fprintf(os.Stderr, "Aborted.\n")
			return nil
		}
	}

	// armis:ignore cwe:73 cwe:22 reason:DetectShells derives each RCFile by joining $HOME with a fixed filename (.bashrc/.zshrc/.config/fish/config.fish); editing the user's own shell RC files is the entire purpose of `supply-chain uninit`, and RemoveFunctions only strips armis-cli supply-chain blocks it previously injected — no externally-controlled path component is ever introduced
	rcModified, err := supplychain.RemoveFunctions(shells)
	if err != nil {
		return err
	}

	npmrcChanged, err := supplychain.RemoveNpmrcMarker(supplychain.NpmrcFileName)
	if err != nil {
		return fmt.Errorf("removing marker from %s: %w", supplychain.NpmrcFileName, err)
	}

	fmt.Fprintf(os.Stderr, "\n")
	for _, f := range rcModified {
		fmt.Fprintf(os.Stderr, "  %s Cleaned: %s\n", s.SuccessText.Render(output.IconSuccess), s.Bold.Render(f))
	}
	if npmrcChanged {
		fmt.Fprintf(os.Stderr, "  %s Cleaned: %s\n", s.SuccessText.Render(output.IconSuccess), s.Bold.Render(supplychain.NpmrcFileName))
	}

	// Only the shell RC edits need a shell reload to take effect; an .npmrc-only
	// cleanup does not, so tailor the closing line to what actually changed.
	if len(rcModified) > 0 {
		fmt.Fprintf(os.Stderr, "\n%s Restart your shell or source the modified file(s).\n", s.SuccessText.Render("Done!"))
	} else {
		fmt.Fprintf(os.Stderr, "\n%s\n", s.SuccessText.Render("Done!"))
	}
	return nil
}
