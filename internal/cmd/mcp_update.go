package cmd

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/install"
	"github.com/spf13/cobra"
)

var mcpUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update the installed MCP servers to the latest version",
	Long: `Update the Armis AppSec MCP server, and every editor it's registered in, to
the latest version.

Reads the install manifest written by 'armis-cli install' to find out what's
already registered — no editor names needed. Armis Knowledge is updated too
if it was previously installed, or if --with-knowledge is passed.`,
	Example: `  # Update everything the manifest knows about
  armis-cli mcp update

  # Also install/update Armis Knowledge, even if it wasn't set up before
  armis-cli mcp update --with-knowledge

  # Force a reinstall even if already current
  armis-cli mcp update --force`,
	Args: cobra.NoArgs,
	RunE: runMCPUpdate,
}

func init() {
	mcpCmd.AddCommand(mcpUpdateCmd)
	mcpUpdateCmd.Flags().Bool("force", false, "Force reinstall even if already up to date")
	mcpUpdateCmd.Flags().Bool("with-knowledge", false, "Also update Armis Knowledge for the same targets, even if not previously installed")
}

func runMCPUpdate(cmd *cobra.Command, _ []string) error {
	force, err := cmd.Flags().GetBool("force")
	if err != nil {
		return fmt.Errorf("reading --force flag: %w", err)
	}
	withKnowledgeFlag, err := cmd.Flags().GetBool("with-knowledge")
	if err != nil {
		return fmt.Errorf("reading --with-knowledge flag: %w", err)
	}

	ei := install.NewEditorInstaller()
	manifest := install.ReadManifest(ei.PluginDir())
	if manifest == nil {
		return fmt.Errorf("Armis AppSec MCP server is not installed — run: armis-cli install") //nolint:staticcheck // proper noun
	}

	fmt.Fprintln(os.Stderr, "Checking for updates...")
	if err := ei.FetchPlugin(force); err != nil {
		if errors.Is(err, install.ErrAlreadyCurrent) {
			fmt.Fprintf(os.Stderr, "Armis AppSec MCP server v%s is already up to date.\n\n", ei.InstalledVersion())
		} else {
			return fmt.Errorf("update failed: %w", err)
		}
	} else {
		fmt.Fprintf(os.Stderr, "MCP server updated to v%s.\n\n", ei.InstalledVersion())
	}
	manifest.PluginVersion = ei.InstalledVersion()

	var registered []string
	var failed []string
	var kt knowledgeTargets

	editorIDs := make([]install.EditorID, 0, len(manifest.Editors))
	for id := range manifest.Editors {
		editorIDs = append(editorIDs, id)
	}
	sort.Slice(editorIDs, func(i, j int) bool { return editorIDs[i] < editorIDs[j] })

	for _, id := range editorIDs {
		e, ok := install.EditorByID(id)
		if !ok {
			fmt.Fprintf(os.Stderr, "  ⚠ %s: no longer supported by this CLI version — skipping\n", id)
			failed = append(failed, string(id))
			continue
		}
		if err := e.Register(ei.PluginDir()); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", e.Name, err)
			failed = append(failed, e.Name)
		} else {
			fmt.Fprintf(os.Stderr, "  ✓ %s\n", e.Name)
			registered = append(registered, e.Name)
			manifest.AddEditor(e.ID, e.ConfigPath(), install.ConfigFormat(e.ID))
			kt.editors = append(kt.editors, e)
		}

		if hc, ok := install.HookClientByID(install.HookClientID(id)); ok {
			if err := install.InstallNativeHook(hc, ei.PluginDir()); err != nil {
				fmt.Fprintf(os.Stderr, "  ⚠ %s (hooks): %v\n", e.Name, err)
			}
		}
	}

	if manifest.Claude != nil {
		ci, ciErr := install.NewClaudeInstaller()
		if ciErr != nil {
			fmt.Fprintf(os.Stderr, "  ✗ Claude Code: %v\n", ciErr)
			failed = append(failed, "Claude Code")
		} else if err := ci.Install(); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ Claude Code: %v\n", err)
			failed = append(failed, "Claude Code")
		} else {
			fmt.Fprintf(os.Stderr, "  ✓ Claude Code v%s\n", ci.InstalledVersion())
			registered = append(registered, "Claude Code")
			manifest.SetClaude(ci.PluginCacheDir())
			kt.claude = true
		}
	}

	if manifest.Codex != nil {
		if err := install.RegisterCodexMCP(ei.PluginDir()); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ Codex CLI (MCP): %v\n", err)
			failed = append(failed, "Codex CLI")
		} else {
			fmt.Fprintf(os.Stderr, "  ✓ Codex CLI (MCP)\n")
			registered = append(registered, "Codex CLI")
			manifest.SetCodex(install.CodexConfigPath())
			kt.codex = true
		}
		if hc, ok := install.HookClientByID(install.HookClientCodex); ok {
			if err := install.InstallNativeHook(hc, ei.PluginDir()); err != nil {
				fmt.Fprintf(os.Stderr, "  ⚠ Codex CLI (hooks): %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "  ✓ Codex CLI (hooks)\n")
			}
		}
	}

	withKnowledge := withKnowledgeFlag || manifest.Knowledge != nil
	var kres knowledgeResult
	if withKnowledge {
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Updating Armis Knowledge...")
		kres = installKnowledgeFor(kt, force, manifest)
	}

	if err := install.WriteManifest(manifest); err != nil {
		fmt.Fprintf(os.Stderr, "  ⚠ Could not write install manifest: %v\n", err)
	}

	fmt.Fprintln(os.Stderr, "")
	if len(registered) > 0 {
		fmt.Fprintf(os.Stderr, "Updated: %s\n", strings.Join(registered, ", "))
	}
	if len(failed) > 0 {
		fmt.Fprintf(os.Stderr, "Failed: %s\n", strings.Join(failed, ", "))
	}
	if withKnowledge {
		printKnowledgeResult(kres)
	}

	return nil
}
