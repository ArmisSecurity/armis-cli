package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/cmd/cmdutil"
	"github.com/ArmisSecurity/armis-cli/internal/install"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

var uninstallCmd = &cobra.Command{
	Use:   "uninstall [editor...]",
	Short: "Remove the Armis security scanner MCP server",
	Long: `Remove the Armis AppSec MCP server from your coding tools.

With no arguments, removes the plugin from all editors and deletes plugin files.
Specify editor names to remove from specific tools only (plugin files are kept).

Use --keep-credentials to preserve the .env file for easy reinstall.
Use --force to skip the confirmation prompt.

For a list of valid editor names, run: armis-cli install --help`,
	Example: `  # Remove from all editors and delete plugin
  armis-cli uninstall

  # Remove from specific editors only (keep plugin)
  armis-cli uninstall cursor vscode

  # Remove all but preserve credentials
  armis-cli uninstall --keep-credentials

  # Skip confirmation
  armis-cli uninstall --force

  # Machine-readable result (JSON on stdout, progress on stderr; skips the
  # confirmation prompt)
  armis-cli uninstall --format json`,
	RunE: runUninstall,
}

func init() {
	rootCmd.AddCommand(uninstallCmd)
	uninstallCmd.Flags().Bool("keep-credentials", false, "Preserve the .env credentials file")
	uninstallCmd.Flags().Bool("force", false, "Skip confirmation prompt")
	uninstallCmd.Flags().StringP("format", "f", formatHuman, "Output format: human, json (json writes one document to stdout and implies --force)")
}

func runUninstall(cmd *cobra.Command, args []string) error {
	keepCreds, err := cmd.Flags().GetBool("keep-credentials")
	if err != nil {
		return fmt.Errorf("reading --keep-credentials flag: %w", err)
	}
	force, err := cmd.Flags().GetBool("force")
	if err != nil {
		return fmt.Errorf("reading --force flag: %w", err)
	}

	formatStr, err := cmd.Flags().GetString("format")
	if err != nil {
		return fmt.Errorf("reading --format flag: %w", err)
	}
	format, err := parseOutputFormat(formatStr)
	if err != nil {
		return err
	}

	u := install.NewUninstaller()
	rep := newUninstallReport()

	if len(args) > 0 {
		err = uninstallTargets(u, args, rep)
	} else {
		// JSON mode is for scripts, so there is nobody to answer the prompt.
		err = uninstallAll(u, keepCreds, force || format == formatJSON, rep)
	}
	return finishUninstall(format, nil, rep, err)
}

func uninstallAll(u *install.Uninstaller, keepCreds, force bool, rep *uninstallReport) error {
	styled := cli.ColorsEnabled()

	var titleStyle, separatorStyle, successMark, warnMark, dimStyle lipgloss.Style
	if styled {
		titleStyle = lipgloss.NewStyle().Bold(true).Foreground(cmdutil.BrandAccent)
		separatorStyle = lipgloss.NewStyle().Foreground(cmdutil.BrandSeparator)
		successMark = lipgloss.NewStyle().Foreground(cmdutil.BrandSuccess)
		warnMark = lipgloss.NewStyle().Foreground(cmdutil.BrandWarn)
		dimStyle = lipgloss.NewStyle().Foreground(cmdutil.BrandMuted)
	}

	if !force {
		if styled {
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintf(os.Stderr, "  %s\n", titleStyle.Render("Armis AppSec MCP Server Uninstall"))
			fmt.Fprintf(os.Stderr, "  %s\n", separatorStyle.Render("──────────────────────────────────"))
			fmt.Fprintln(os.Stderr, "")
			msg := "  This will remove the MCP server from all editors and delete plugin files."
			if keepCreds {
				msg += "\n  Credentials (.env) will be preserved."
			}
			fmt.Fprintln(os.Stderr, dimStyle.Render(msg))
			fmt.Fprintln(os.Stderr, "")
		} else {
			msg := "This will remove the Armis AppSec MCP server from all editors and delete plugin files."
			if keepCreds {
				msg += "\nCredentials (.env) will be preserved."
			}
			fmt.Fprintln(os.Stderr, msg)
		}
		prompt := "Continue?"
		if styled {
			prompt = "  Continue?"
		}
		if !confirm(prompt) {
			fmt.Fprintln(os.Stderr, "  Aborted.")
			return nil
		}
		fmt.Fprintln(os.Stderr, "")
	}

	// Remove native hook configs from all AI clients
	hookErrs := make([]error, len(install.AllHookClients))
	for i, hc := range install.AllHookClients {
		err := install.RemoveNativeHook(hc)
		hookErrs[i] = err
		if err != nil {
			if styled {
				fmt.Fprintf(os.Stderr, "  %s Hook removal (%s): %v\n", warnMark.Render("⚠"), hc.Name, err)
			} else {
				fmt.Fprintf(os.Stderr, "  ⚠ Hook removal (%s): %v\n", hc.Name, err)
			}
		}
	}

	deregistered, warnings := u.DeregisterAllEditors()
	for _, name := range deregistered {
		if id, ok := editorIDForName(name); ok {
			rep.removed(id, name)
		}
		if styled {
			fmt.Fprintf(os.Stderr, "  %s Removed from %s\n", successMark.Render("✓"), name)
		} else {
			fmt.Fprintf(os.Stderr, "  ✓ Removed from %s\n", name)
		}
	}
	for _, w := range warnings {
		rep.editorWarning(w)
		if styled {
			fmt.Fprintf(os.Stderr, "  %s %s\n", warnMark.Render("⚠"), w)
		} else {
			fmt.Fprintf(os.Stderr, "  ⚠ %s\n", w)
		}
	}

	if err := u.DeregisterClaude(); err != nil {
		rep.failed(targetClaude, "Claude Code", err.Error())
		if styled {
			fmt.Fprintf(os.Stderr, "  %s Claude Code: %v\n", warnMark.Render("⚠"), err)
		} else {
			fmt.Fprintf(os.Stderr, "  ⚠ Claude Code: %v\n", err)
		}
	} else {
		rep.removed(targetClaude, "Claude Code")
		if styled {
			fmt.Fprintf(os.Stderr, "  %s Removed from Claude Code\n", successMark.Render("✓"))
		} else {
			fmt.Fprintf(os.Stderr, "  ✓ Removed from Claude Code\n")
		}
	}

	if removed, err := install.DeregisterCodexMCP(); err != nil {
		rep.failed(targetCodex, "Codex CLI", err.Error())
		if styled {
			fmt.Fprintf(os.Stderr, "  %s Codex CLI: %v\n", warnMark.Render("⚠"), err)
		} else {
			fmt.Fprintf(os.Stderr, "  ⚠ Codex CLI: %v\n", err)
		}
	} else if removed {
		rep.removed(targetCodex, "Codex CLI")
		if styled {
			fmt.Fprintf(os.Stderr, "  %s Removed from Codex CLI\n", successMark.Render("✓"))
		} else {
			fmt.Fprintf(os.Stderr, "  ✓ Removed from Codex CLI\n")
		}
	}

	// rep.hook only records a successful removal against a client already in
	// the report, so it runs once the deregistration steps have added them.
	for i, hc := range install.AllHookClients {
		rep.hook(hc, hookErrs[i])
	}

	// Remove Armis Knowledge whenever the manifest records it — no flag. Leaving
	// an MCP entry pointing at a deleted plugin dir would break the user's agents.
	if u.HasKnowledge() {
		kremoved, kwarnings := u.RemoveKnowledge(keepCreds)
		rep.Knowledge = knowledgeUninstallReport(kremoved, kwarnings)
		if len(kremoved) > 0 {
			if styled {
				fmt.Fprintf(os.Stderr, "  %s Removed Armis Knowledge (%s)\n",
					successMark.Render("✓"), strings.Join(kremoved, ", "))
			} else {
				fmt.Fprintf(os.Stderr, "  ✓ Removed Armis Knowledge (%s)\n", strings.Join(kremoved, ", "))
			}
		}
		for _, w := range kwarnings {
			if styled {
				fmt.Fprintf(os.Stderr, "  %s %s\n", warnMark.Render("⚠"), w)
			} else {
				fmt.Fprintf(os.Stderr, "  ⚠ %s\n", w)
			}
		}
	}

	// Remove the git pre-commit hook from the current repo BEFORE deleting plugin
	// files. The hook execs <pluginDir>/git-hooks/pre-commit; once RemovePluginFiles
	// deletes that path, an orphaned hook would break every future commit with
	// "no such file". RemovePreCommit is a no-op outside a git repo or when no
	// Armis section is present, so it is safe to call unconditionally.
	preCommitRemoved := false
	if repoRoot := install.DetectGitRoot(); repoRoot != "" {
		// Record whether a hook was actually present first: RemovePreCommit
		// returns nil for the no-op cases too (no hook file, no Armis section),
		// so a nil result alone would wrongly claim a removal. Only report one
		// when a hook was installed before the call and is gone after it.
		hadHook := install.IsPreCommitInstalled(repoRoot)
		if err := install.RemovePreCommit(repoRoot); err != nil {
			rep.PreCommit = &uninstallStep{Status: reportFail, Detail: err.Error()}
			if styled {
				fmt.Fprintf(os.Stderr, "  %s Pre-commit hook: %v\n", warnMark.Render("⚠"), err)
			} else {
				fmt.Fprintf(os.Stderr, "  ⚠ Pre-commit hook: %v\n", err)
			}
		} else if hadHook {
			preCommitRemoved = true
			rep.PreCommit = &uninstallStep{Status: reportOK, Detail: "removed"}
		}
	}
	if rep.PreCommit == nil {
		rep.PreCommit = &uninstallStep{Status: reportSkip}
	}

	rep.PluginFiles = &uninstallPluginFiles{Status: reportOK, CredentialsKept: keepCreds}
	if err := u.RemovePluginFiles(keepCreds); err != nil {
		rep.PluginFiles.Status = reportFail
		rep.PluginFiles.Detail = err.Error()
		if styled {
			fmt.Fprintf(os.Stderr, "  %s Plugin files: %v\n", warnMark.Render("⚠"), err)
		} else {
			fmt.Fprintf(os.Stderr, "  ⚠ Plugin files: %v\n", err)
		}
	} else if keepCreds {
		if styled {
			fmt.Fprintf(os.Stderr, "  %s Plugin files removed (credentials preserved)\n", successMark.Render("✓"))
		} else {
			fmt.Fprintln(os.Stderr, "  ✓ Plugin files removed (credentials preserved)")
		}
	} else {
		if styled {
			fmt.Fprintf(os.Stderr, "  %s Plugin files removed\n", successMark.Render("✓"))
		} else {
			fmt.Fprintln(os.Stderr, "  ✓ Plugin files removed")
		}
	}

	fmt.Fprintln(os.Stderr, "")
	if styled {
		fmt.Fprintf(os.Stderr, "  %s Armis AppSec MCP server uninstalled.\n", successMark.Render("✓"))
	} else {
		fmt.Fprintln(os.Stderr, "Armis AppSec MCP server uninstalled.")
	}
	if preCommitRemoved {
		msg := "Pre-commit hook removed from this repository. Run `armis-cli hook init --remove` in other repos."
		if styled {
			fmt.Fprintf(os.Stderr, "  %s\n", dimStyle.Render(msg))
		} else {
			fmt.Fprintln(os.Stderr, msg)
		}
	}
	fmt.Fprintln(os.Stderr, "")
	return nil
}

func uninstallTargets(u *install.Uninstaller, targets []string, rep *uninstallReport) error {
	styled := cli.ColorsEnabled()

	var successMark, failMark, warnMark, dimStyle lipgloss.Style
	if styled {
		successMark = lipgloss.NewStyle().Foreground(cmdutil.BrandSuccess)
		failMark = lipgloss.NewStyle().Foreground(cmdutil.BrandError)
		warnMark = lipgloss.NewStyle().Foreground(cmdutil.BrandWarn)
		dimStyle = lipgloss.NewStyle().Foreground(cmdutil.BrandMuted)
	}

	printSuccess := func(msg string) {
		if styled {
			fmt.Fprintf(os.Stderr, "  %s %s\n", successMark.Render("✓"), msg)
		} else {
			fmt.Fprintf(os.Stderr, "  ✓ %s\n", msg)
		}
	}
	printFail := func(msg string) {
		if styled {
			fmt.Fprintf(os.Stderr, "  %s %s\n", failMark.Render("✗"), msg)
		} else {
			fmt.Fprintf(os.Stderr, "  ✗ %s\n", msg)
		}
	}
	printWarn := func(msg string) {
		if styled {
			fmt.Fprintf(os.Stderr, "  %s %s\n", warnMark.Render("⚠"), msg)
		} else {
			fmt.Fprintf(os.Stderr, "  ⚠ %s\n", msg)
		}
	}

	for _, name := range targets {
		switch name {
		case targetClaude:
			if err := u.DeregisterClaude(); err != nil {
				printFail(fmt.Sprintf("Claude Code: %v", err))
				rep.failed(targetClaude, "Claude Code", err.Error())
			} else {
				printSuccess("Claude Code")
				rep.removed(targetClaude, "Claude Code")
			}
		case targetCodex:
			if removed, err := install.DeregisterCodexMCP(); err != nil {
				printFail(fmt.Sprintf("Codex CLI: %v", err))
				rep.failed(targetCodex, "Codex CLI", err.Error())
			} else if removed {
				printSuccess("Codex CLI")
				rep.removed(targetCodex, "Codex CLI")
			}
		case targetCopilot:
			if err := u.DeregisterEditor(install.EditorCopilotCLI); err != nil {
				printFail(fmt.Sprintf("Copilot CLI: %v", err))
				rep.failed(targetCopilot, "Copilot CLI", err.Error())
			} else {
				printSuccess("Copilot CLI")
				rep.removed(targetCopilot, "Copilot CLI")
			}
		case "jetbrains":
			printWarn("JetBrains: Remove .jb-mcp.json from your project root manually.")
			rep.warned("jetbrains", "JetBrains", "Remove .jb-mcp.json from your project root manually.")
		case "devin":
			printWarn("Devin: Remove the MCP server via the Devin web UI.")
			rep.warned("devin", "Devin", "Remove the MCP server via the Devin web UI.")
		case "openhands":
			printWarn("OpenHands: Remove the MCP server via the OpenHands web UI.")
			rep.warned("openhands", "OpenHands", "Remove the MCP server via the OpenHands web UI.")
		case "aider":
			printWarn("Aider: No MCP configuration to remove.")
			rep.client("aider", "Aider").Detail = "no MCP configuration to remove"
		default:
			id := install.EditorID(name)
			e, ok := install.EditorByID(id)
			if !ok {
				printFail(fmt.Sprintf("Unknown editor: %s", name))
				rep.failed(name, name, "unknown editor")
				continue
			}
			if err := u.DeregisterEditor(id); err != nil {
				printFail(fmt.Sprintf("%s: %v", e.Name, err))
				rep.failed(string(id), e.Name, err.Error())
			} else {
				printSuccess(e.Name)
				rep.removed(string(id), e.Name)
			}
		}

		if hc, ok := install.HookClientByID(install.HookClientID(name)); ok {
			err := install.RemoveNativeHook(hc)
			rep.hook(hc, err)
			if err != nil {
				printWarn(fmt.Sprintf("Hook config (%s): %v", hc.Name, err))
			}
		}
	}

	// Update manifest if one exists
	manifest := install.ReadManifest(u.PluginDir())
	if manifest != nil {
		for _, name := range targets {
			switch name {
			case targetClaude:
				manifest.Claude = nil
			case targetCodex:
				manifest.Codex = nil
			case targetCopilot:
				manifest.RemoveEditor(install.EditorCopilotCLI)
			default:
				manifest.RemoveEditor(install.EditorID(name))
			}
		}
		if err := install.WriteManifest(manifest); err != nil {
			printWarn(fmt.Sprintf("Could not update install manifest: %v", err))
		}
	}

	rep.PluginFiles = &uninstallPluginFiles{Status: reportSkip, Detail: "kept: other editors may still use them", CredentialsKept: true}
	rep.PreCommit = &uninstallStep{Status: reportSkip}

	fmt.Fprintln(os.Stderr, "")
	if styled {
		fmt.Fprintln(os.Stderr, dimStyle.Render("  Plugin files kept (other editors may still use them)."))
	} else {
		fmt.Fprintln(os.Stderr, "Plugin files kept (other editors may still use them).")
	}
	fmt.Fprintln(os.Stderr, "")
	return nil
}

// confirmOut is where confirm() writes its prompt. It defaults to stderr (all
// interactive output goes to stderr), but is a package var so tests can redirect
// it to io.Discard — the unterminated prompt otherwise corrupts gotestsum's
// go-test-json parser and produces false failures under `make test`.
var confirmOut io.Writer = os.Stderr

func confirm(prompt string) bool {
	_, _ = fmt.Fprintf(confirmOut, "%s [y/N] ", prompt)
	scanner := bufio.NewScanner(io.LimitReader(os.Stdin, 256))
	// The scanner's attribution of this finding drifts between this line and the
	// func signature above across runs; the directive lives here, at the actual
	// sink, so the upward scan finds it regardless of which line gets flagged.
	// armis:ignore cwe:253 reason:Scan() returns false on EOF/error which is correct default-deny behavior (returns false = no confirmation)
	if !scanner.Scan() {
		return false
	}
	line := scanner.Text()
	answer := strings.TrimSpace(strings.ToLower(line))
	return answer == "y" || answer == "yes"
}
