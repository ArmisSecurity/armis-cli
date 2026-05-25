package cmd

import (
	"github.com/spf13/cobra"
)

var hookCmd = &cobra.Command{
	Use:   "hook",
	Short: "Manage security scanning hooks",
	Long: `Manage Armis security scanning hooks for AI coding clients and git.

Armis hooks enforce security scanning at two levels:

  Native hooks — block tool calls before they execute (per-client config)
    Supported: Claude Code, Cursor, Gemini CLI, Codex CLI, Copilot CLI, Cline

  Git pre-commit — block commits unless scanning passed (per-repo)
    Works with any tool, catches manual commits too.

Native hooks are installed automatically by 'armis-cli install'.
Use 'armis-cli hook init' to add the git pre-commit hook to a repo.`,
}

func init() {
	rootCmd.AddCommand(hookCmd)
}
