package cmd

import (
	"fmt"
	"os"

	"github.com/ArmisSecurity/armis-cli/internal/install"
	"github.com/spf13/cobra"
)

var hookInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Install git pre-commit hook in the current repository",
	Long: `Install the Armis security scanning hook into .git/hooks/pre-commit.

The hook verifies that code was scanned before allowing commits. It checks
for the .scan-pass file created by the Armis MCP server's scan_diff() tool.

If a pre-commit hook already exists, the Armis section is appended.`,
	Example: `  # Install pre-commit hook (fail-closed: blocks commit on findings)
  armis-cli hook init

  # Install in fail-open mode (warns but allows commit)
  armis-cli hook init --fail-open

  # Remove the pre-commit hook
  armis-cli hook init --remove`,
	RunE: runHookInit,
}

func init() {
	hookCmd.AddCommand(hookInitCmd)
	hookInitCmd.Flags().Bool("fail-open", false, "Warn on findings but allow commit (default: block)")
	hookInitCmd.Flags().Bool("remove", false, "Remove the Armis pre-commit hook")
}

func runHookInit(cmd *cobra.Command, _ []string) error {
	remove, _ := cmd.Flags().GetBool("remove")
	failOpen, _ := cmd.Flags().GetBool("fail-open")

	repoRoot := install.DetectGitRoot()
	if repoRoot == "" {
		return fmt.Errorf("not inside a git repository")
	}

	if remove {
		if err := install.RemovePreCommit(repoRoot); err != nil {
			return fmt.Errorf("removing pre-commit hook: %w", err)
		}
		fmt.Fprintln(os.Stderr, "Armis pre-commit hook removed.")
		return nil
	}

	ei := install.NewEditorInstaller()
	pluginDir := ei.PluginDir()
	if _, err := os.Stat(pluginDir); os.IsNotExist(err) {
		return fmt.Errorf("Armis MCP server not installed — run 'armis-cli install' first") //nolint:staticcheck // proper noun
	}

	opts := install.PreCommitOpts{FailOpen: failOpen}
	if err := install.InstallPreCommit(repoRoot, pluginDir, opts); err != nil {
		return err
	}

	if install.IsPreCommitInstalled(repoRoot) {
		mode := "fail-closed"
		if failOpen {
			mode = "fail-open"
		}
		fmt.Fprintf(os.Stderr, "Pre-commit hook installed (%s): %s/.git/hooks/pre-commit\n", mode, repoRoot)
		fmt.Fprintln(os.Stderr, "Commits will be verified against the scan-pass file.")
	}
	return nil
}
