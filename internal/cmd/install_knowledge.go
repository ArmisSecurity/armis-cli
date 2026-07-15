package cmd

import (
	"fmt"
	"os"

	"github.com/ArmisSecurity/armis-cli/internal/install"
	"github.com/spf13/cobra"
)

// installKnowledgeCmd registers the Armis Knowledge plugin with Claude Code.
//
// Unlike `armis-cli install` (the security scanner MCP), this drives the
// official `claude` CLI to add the knowledge marketplace and install a plugin
// from it — the scanner installer hand-writes registry JSON for a self-hosted
// "directory" marketplace, but the knowledge plugin is a "github" marketplace
// with no releases, so only the CLI can clone it and populate the plugin cache.
var installKnowledgeCmd = &cobra.Command{
	Use:   "knowledge",
	Short: "Install the Armis Knowledge plugin for Claude Code",
	Long: `Install the Armis Knowledge plugin for Claude Code.

Adds the org's knowledge base — standards, CWE remediation, and framework /
technology guidance — as slash commands (/knowledge, /cwe-fix, /cwe-fix-report,
/framework-guidance, /tech-guidance) that your agent can also call on its own.

This drives the Claude Code CLI (claude plugin marketplace add + install), so
Claude Code must be installed. Credentials are read from ARMIS_CLIENT_ID and
ARMIS_CLIENT_SECRET at runtime; the tenant is resolved server-side.

Two variants — pick one per environment. They register identical slash commands
and cannot run side by side, so switching variants auto-removes the other:
  --variant skills   Shell-skills, Claude Code only, no Python (default)
  --variant mcp      MCP server; needs Python, adds the agentic /ask command

The backend environment follows --dev (dev backend) and defaults to prod.`,
	Example: `  # Install the shell-skills variant (prod) — no Python required
  armis-cli install knowledge

  # Install the MCP variant (adds /ask; needs Python)
  armis-cli install knowledge --variant mcp

  # Point at the dev backend (registers /knowledge-dev, etc.)
  armis-cli install knowledge --dev`,
	Args: cobra.NoArgs,
	RunE: runInstallKnowledge,
}

func init() {
	installCmd.AddCommand(installKnowledgeCmd)
	installKnowledgeCmd.Flags().String("variant", "skills", "Plugin variant: skills (no Python) or mcp (adds /ask)")
}

func runInstallKnowledge(cmd *cobra.Command, _ []string) error {
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

	// Environment follows the global --dev flag; prod is the default everyone uses.
	env := install.KnowledgeEnvProd
	if useDev {
		env = install.KnowledgeEnvDev
	}

	ki := install.NewKnowledgeInstaller(variant, env)

	if err := ki.CheckClaudeCLI(); err != nil {
		return err
	}

	// The MCP variant bootstraps a Python venv on first launch (inside Claude
	// Code). Warn early if Python is missing so the failure isn't deferred to a
	// confusing cold-start error the first time a knowledge command runs.
	if variant == install.KnowledgeVariantMCP {
		if perr := install.CheckPython(); perr != nil {
			fmt.Fprintf(os.Stderr, "Warning: the MCP variant needs Python at runtime — %v\n\n", perr)
		}
	}

	fmt.Fprintf(os.Stderr, "Installing %s for Claude Code...\n", ki.PluginRef())
	replaced, err := ki.Install()
	if err != nil {
		return fmt.Errorf("knowledge plugin installation failed: %w", err)
	}
	// The two variants share slash commands and cannot coexist; report when the
	// sibling was swapped out so the state change is visible, not silent.
	if replaced != "" {
		fmt.Fprintf(os.Stderr, "  ✓ Removed conflicting %s (same commands)\n", replaced)
	}
	fmt.Fprintf(os.Stderr, "  ✓ %s\n\n", ki.PluginRef())

	if install.CredentialsPresent() {
		fmt.Fprintln(os.Stderr, "Credentials detected. Restart Claude Code to load the plugin.")
	} else {
		fmt.Fprintln(os.Stderr, "Next steps:")
		fmt.Fprintln(os.Stderr, "  1. Export your credentials (copy from the knowledge webapp's /settings/integrations):")
		fmt.Fprintln(os.Stderr, "     export ARMIS_CLIENT_ID=<your-client-id>")
		fmt.Fprintln(os.Stderr, "     export ARMIS_CLIENT_SECRET=<your-client-secret>")
		fmt.Fprintln(os.Stderr, "  2. Restart Claude Code")
	}
	return nil
}
