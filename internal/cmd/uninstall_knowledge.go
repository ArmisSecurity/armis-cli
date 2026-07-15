package cmd

import (
	"fmt"
	"os"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/cmd/cmdutil"
	"github.com/ArmisSecurity/armis-cli/internal/install"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

// uninstallKnowledgeCmd removes the Armis Knowledge plugin from Claude Code.
// Mirrors installKnowledgeCmd: it drives the `claude` CLI rather than editing
// registry JSON, so install/uninstall stay symmetric.
var uninstallKnowledgeCmd = &cobra.Command{
	Use:   "knowledge",
	Short: "Remove the Armis Knowledge plugin from Claude Code",
	Long: `Remove the Armis Knowledge plugin from Claude Code.

Drives the Claude Code CLI (claude plugin uninstall). Use --variant to match the
plugin you installed; the backend environment follows --dev. The shared
knowledge marketplace registration is left in place — other environments may
still use it.`,
	Example: `  # Remove the shell-skills variant (prod)
  armis-cli uninstall knowledge

  # Remove the MCP variant
  armis-cli uninstall knowledge --variant mcp`,
	Args: cobra.NoArgs,
	RunE: runUninstallKnowledge,
}

func init() {
	uninstallCmd.AddCommand(uninstallKnowledgeCmd)
	uninstallKnowledgeCmd.Flags().String("variant", "skills", "Plugin variant to remove: skills or mcp")
}

func runUninstallKnowledge(cmd *cobra.Command, _ []string) error {
	variantStr, err := cmd.Flags().GetString("variant")
	if err != nil {
		return fmt.Errorf("reading --variant flag: %w", err)
	}

	var variant install.KnowledgeVariant
	switch variantStr {
	case "skills":
		variant = install.KnowledgeVariantSkills
	case "mcp":
		variant = install.KnowledgeVariantMCP
	default:
		return fmt.Errorf("unknown --variant %q (want \"skills\" or \"mcp\")", variantStr)
	}

	env := install.KnowledgeEnvProd
	if useDev {
		env = install.KnowledgeEnvDev
	}

	ki := install.NewKnowledgeInstaller(variant, env)
	if err := ki.CheckClaudeCLI(); err != nil {
		return err
	}

	successMark := "✓"
	if cli.ColorsEnabled() {
		successMark = lipgloss.NewStyle().Foreground(cmdutil.BrandSuccess).Render("✓")
	}

	fmt.Fprintf(os.Stderr, "Removing %s from Claude Code...\n", ki.PluginRef())
	if err := ki.Uninstall(); err != nil {
		return fmt.Errorf("knowledge plugin uninstall failed: %w", err)
	}
	fmt.Fprintf(os.Stderr, "  %s Removed %s\n", successMark, ki.PluginRef())
	return nil
}
