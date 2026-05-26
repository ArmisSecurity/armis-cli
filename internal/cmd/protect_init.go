package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/protect"
	"github.com/spf13/cobra"
)

var (
	protectInitMode   string
	protectInitDryRun bool
	protectInitYes    bool
)

var protectInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Set up local package age enforcement",
	Long: `Configure your shell to enforce package release age policies during installations.

This wraps your package manager (npm) so that armis-cli can filter out recently-published
package versions before they reach your local install. Packages older than the policy
threshold (default 72h) install normally.

Three modes are available:
  rc   — Inject shell functions into ~/.bashrc / ~/.zshrc (default, interactive)
  env  — Print an eval command for CI or manual sourcing
  npmrc — Write registry override to .npmrc (project-level)

Run 'armis-cli protect uninit' to reverse changes made by this command.`,
	Example: `  # Interactive setup (default)
  armis-cli protect init

  # See what would be modified
  armis-cli protect init --dry-run

  # Non-interactive (CI friendly)
  armis-cli protect init --yes

  # Print eval command for CI
  armis-cli protect init --mode env

  # Write .npmrc override
  armis-cli protect init --mode npmrc`,
	Args: cobra.NoArgs,
	RunE: runProtectInit,
}

func init() {
	protectInitCmd.Flags().StringVar(&protectInitMode, "mode", "rc", "Setup mode: rc (shell RC injection), env (eval command), npmrc (project .npmrc)")
	protectInitCmd.Flags().BoolVar(&protectInitDryRun, "dry-run", false, "Show what would be modified without making changes")
	protectInitCmd.Flags().BoolVar(&protectInitYes, "yes", false, "Skip confirmation prompt")

	protectCmd.AddCommand(protectInitCmd)
}

func runProtectInit(_ *cobra.Command, _ []string) error {
	pms := []string{"npm"}

	switch protectInitMode {
	case "env":
		return runInitEnv(pms)
	case "npmrc":
		return runInitNpmrc()
	case "rc":
		return runInitRC(pms)
	default:
		return fmt.Errorf("unknown mode: %s (valid: rc, env, npmrc)", protectInitMode)
	}
}

func runInitEnv(pms []string) error {
	block := protect.EvalCommand(pms)
	if protectInitDryRun {
		fmt.Fprintf(os.Stderr, "Would print eval command:\n\n")
	}
	fmt.Print(block)
	if !protectInitDryRun {
		fmt.Fprintf(os.Stderr, "\nUsage: eval \"$(armis-cli protect init --mode env)\"\n")
	}
	return nil
}

func runInitNpmrc() error {
	npmrcPath := ".npmrc"
	line := "# armis-cli protect: registry override applied at install time via 'protect wrap'\n"

	if protectInitDryRun {
		fmt.Fprintf(os.Stderr, "Would add comment to %s noting that protect wrap handles registry override.\n", npmrcPath)
		fmt.Fprintf(os.Stderr, "Note: npmrc mode works with 'eval' mode — the registry URL is set dynamically by protect wrap.\n")
		return nil
	}

	content, _ := os.ReadFile(npmrcPath) //nolint:gosec // project .npmrc
	if strings.Contains(string(content), "armis-cli protect") {
		fmt.Fprintf(os.Stderr, "%s already contains armis-cli protect configuration.\n", npmrcPath)
		return nil
	}

	f, err := os.OpenFile(npmrcPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644) //nolint:gosec // project .npmrc
	if err != nil {
		return fmt.Errorf("opening %s: %w", npmrcPath, err)
	}
	defer f.Close() //nolint:errcheck

	if _, err := f.WriteString(line); err != nil {
		return fmt.Errorf("writing %s: %w", npmrcPath, err)
	}

	fmt.Fprintf(os.Stderr, "Updated %s\n", npmrcPath)
	fmt.Fprintf(os.Stderr, "Use with: eval \"$(armis-cli protect init --mode env)\"\n")
	return nil
}

func runInitRC(pms []string) error {
	shells := protect.DetectShells()
	if len(shells) == 0 {
		return fmt.Errorf("no supported shells detected (bash, zsh, or fish)")
	}

	wrapper := protect.GenerateWrapper(shells[0].Name, pms)

	fmt.Fprintf(os.Stderr, "Detected shell(s): ")
	names := make([]string, 0, len(shells))
	for _, s := range shells {
		names = append(names, s.Name+" ("+s.RCFile+")")
	}
	fmt.Fprintf(os.Stderr, "%s\n\n", strings.Join(names, ", "))

	fmt.Fprintf(os.Stderr, "Will inject the following into shell RC file(s):\n\n")
	fmt.Fprintf(os.Stderr, "%s\n", wrapper)

	if protectInitDryRun {
		fmt.Fprintf(os.Stderr, "(dry-run: no changes made)\n")
		return nil
	}

	if !protectInitYes {
		fmt.Fprintf(os.Stderr, "Proceed? [Y/n] ")
		var answer string
		fmt.Scanln(&answer) //nolint:errcheck,gosec // interactive prompt, EOF is fine
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer != "" && answer != "y" && answer != "yes" {
			fmt.Fprintf(os.Stderr, "Aborted.\n")
			return nil
		}
	}

	modified, err := protect.InjectFunctions(shells, pms)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "\n")
	for _, f := range modified {
		fmt.Fprintf(os.Stderr, "  ✓ Modified: %s\n", f)
	}

	fmt.Fprintf(os.Stderr, "\nDone! Restart your shell or run:\n")
	for _, s := range shells {
		fmt.Fprintf(os.Stderr, "  source %s\n", s.RCFile)
	}
	fmt.Fprintf(os.Stderr, "\nPolicy: block packages published less than 72h ago\n")
	fmt.Fprintf(os.Stderr, "Undo:   armis-cli protect uninit\n")

	cli.PrintWarningf("") // ensure colors are initialized for styled output
	return nil
}
