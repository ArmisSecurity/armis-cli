package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/install"
	"github.com/ArmisSecurity/armis-cli/internal/progress"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
)

func runInteractiveInstall(force bool) error {
	theme := getInstallTheme()
	accessible := !cli.ColorsEnabled()

	fmt.Fprintln(os.Stderr, "")
	if accessible {
		fmt.Fprintln(os.Stderr, "  Armis AppSec MCP Server Setup")
		fmt.Fprintln(os.Stderr, "  ─────────────────────────────")
	} else {
		titleStyle := lipgloss.NewStyle().Bold(true).Foreground(brandAccent)
		borderStyle := lipgloss.NewStyle().Foreground(brandSeparator)
		fmt.Fprintf(os.Stderr, "  %s\n", titleStyle.Render("Armis AppSec MCP Server Setup"))
		fmt.Fprintf(os.Stderr, "  %s\n", borderStyle.Render("─────────────────────────────"))
	}
	fmt.Fprintln(os.Stderr, "")

	clientID, clientSecret, skipCreds, credsAborted := collectCredentials(theme, accessible)
	if credsAborted {
		fmt.Fprintln(os.Stderr, "\n  Setup cancelled.")
		return nil
	}

	editorResult := selectEditorsWithCodex(theme, accessible)
	if editorResult.cancelled {
		fmt.Fprintln(os.Stderr, "\n  Setup cancelled.")
		return nil
	}
	selectedEditors := editorResult.editors
	installClaude := editorResult.installClaude
	installCodex := editorResult.installCodex
	if len(selectedEditors) == 0 && !installClaude && !installCodex {
		return fmt.Errorf("no editors selected — nothing to install")
	}

	// --- Execute installation ---
	var successMark, failMark, warnMark string
	if accessible {
		successMark, failMark, warnMark = "[OK]", "[FAIL]", "[WARN]"
	} else {
		successMark = lipgloss.NewStyle().Foreground(brandSuccess).Render("✓")
		failMark = lipgloss.NewStyle().Foreground(brandError).Render("✗")
		warnMark = lipgloss.NewStyle().Foreground(brandWarn).Render("⚠")
	}

	fmt.Fprintln(os.Stderr, "")

	ei := install.NewEditorInstaller()
	needsSharedPlugin := len(selectedEditors) > 0 || installCodex

	if needsSharedPlugin {
		spinner := progress.NewSpinner("Downloading MCP server...", !cli.ColorsEnabled())
		spinner.Start()
		fetchErr := ei.FetchPlugin(force)
		spinner.Stop()
		if fetchErr != nil {
			if errors.Is(fetchErr, install.ErrAlreadyCurrent) {
				fmt.Fprintf(os.Stderr, "  %s MCP server v%s (up to date)\n", successMark, ei.InstalledVersion())
			} else {
				return fmt.Errorf("download failed: %w", fetchErr)
			}
		} else {
			fmt.Fprintf(os.Stderr, "  %s MCP server v%s downloaded\n", successMark, ei.InstalledVersion())
		}

		manifest := install.ReadManifest(ei.PluginDir())
		if manifest == nil {
			manifest = install.NewManifest(ei.PluginDir(), ei.InstalledVersion())
		} else {
			manifest.PluginVersion = ei.InstalledVersion()
		}

		var registered []string
		var failures []string
		for _, e := range selectedEditors {
			if err := e.Register(ei.PluginDir()); err != nil {
				failures = append(failures, fmt.Sprintf("%s: %v", e.Name, err))
			} else {
				registered = append(registered, e.Name)
				manifest.AddEditor(e.ID, e.ConfigPath(), install.ConfigFormat(e.ID))
			}
		}

		if installCodex {
			if err := install.RegisterCodexMCP(ei.PluginDir()); err != nil {
				failures = append(failures, fmt.Sprintf("Codex CLI: %v", err))
			} else {
				registered = append(registered, "Codex CLI")
				manifest.SetCodex(install.CodexConfigPath())
			}
		}

		if len(registered) > 0 {
			if len(registered) <= 3 {
				fmt.Fprintf(os.Stderr, "  %s Registered: %s\n", successMark, strings.Join(registered, ", "))
			} else {
				fmt.Fprintf(os.Stderr, "  %s Registered in %d editors\n", successMark, len(registered))
			}
		}
		for _, f := range failures {
			fmt.Fprintf(os.Stderr, "  %s %s\n", failMark, f)
		}

		if err := install.WriteManifest(manifest); err != nil {
			fmt.Fprintf(os.Stderr, "  %s Could not write install manifest: %v\n", warnMark, err)
		}
	}

	if installClaude {
		ci, ciErr := install.NewClaudeInstaller()
		if ciErr != nil {
			fmt.Fprintf(os.Stderr, "  %s Claude Code: %v\n", failMark, ciErr)
		} else if err := ci.Install(); err != nil {
			fmt.Fprintf(os.Stderr, "  %s Claude Code: %v\n", failMark, err)
		} else {
			fmt.Fprintf(os.Stderr, "  %s Claude Code installed\n", successMark)

			pluginDir := ei.PluginDir()
			manifest := install.ReadManifest(pluginDir)
			if manifest == nil {
				manifest = install.NewManifest(pluginDir, ci.InstalledVersion())
			}
			manifest.SetClaude(ci.PluginCacheDir())
			if err := install.WriteManifest(manifest); err != nil {
				fmt.Fprintf(os.Stderr, "  %s Could not write install manifest: %v\n", warnMark, err)
			}
		}
	}

	// Write credentials if collected
	// armis:ignore cwe:522 cwe:312 reason:CLI stores credentials in .env with 0600 perms; standard local auth config pattern
	if !skipCreds && clientID != "" && clientSecret != "" {
		if needsSharedPlugin {
			// armis:ignore cwe:522 cwe:312 reason:envPath from ei.EnvFilePath() (known plugin dir); file written with 0600 perms
			if err := install.WriteEnvFromValues(ei.EnvFilePath(), clientID, clientSecret); err != nil {
				fmt.Fprintf(os.Stderr, "  %s Failed to write credentials: %v\n", warnMark, err)
			}
		}
		if installClaude {
			ci, err := install.NewClaudeInstaller()
			if err == nil {
				// armis:ignore cwe:522 reason:envPath from ci.EnvFilePath() (known plugin dir); file written with 0600 perms
				if err := install.WriteEnvFromValues(ci.EnvFilePath(), clientID, clientSecret); err != nil {
					fmt.Fprintf(os.Stderr, "  %s Failed to write Claude credentials: %v\n", warnMark, err)
				}
			}
		}
	}

	// --- Security scanning hooks ---
	fmt.Fprintln(os.Stderr, "")
	selectedHookClients, installPreCommit := offerHookSetup(theme, accessible, installClaude)

	// Download plugin if hooks need it and it wasn't already fetched
	if !needsSharedPlugin && (len(selectedHookClients) > 0 || installPreCommit) {
		spinner := progress.NewSpinner("Downloading MCP server...", !cli.ColorsEnabled())
		spinner.Start()
		fetchErr := ei.FetchPlugin(force)
		spinner.Stop()
		if fetchErr != nil && !errors.Is(fetchErr, install.ErrAlreadyCurrent) {
			fmt.Fprintf(os.Stderr, "  %s MCP server download failed: %v\n", failMark, fetchErr)
		}
	}

	if len(selectedHookClients) > 0 {
		fmt.Fprintln(os.Stderr, "")
		var hookOK []string
		var hookFail []string
		for _, hc := range selectedHookClients {
			if err := install.InstallNativeHook(hc, ei.PluginDir()); err != nil {
				hookFail = append(hookFail, fmt.Sprintf("%s: %v", hc.Name, err))
			} else {
				hookOK = append(hookOK, hc.Name)
			}
		}
		if len(hookOK) > 0 {
			fmt.Fprintf(os.Stderr, "  %s Native hooks configured (%s)\n", successMark, strings.Join(hookOK, ", "))
		}
		for _, f := range hookFail {
			fmt.Fprintf(os.Stderr, "  %s %s\n", warnMark, f)
		}
	}

	if installPreCommit {
		repoRoot := install.DetectGitRoot()
		if repoRoot != "" {
			opts := install.PreCommitOpts{FailOpen: false}
			if err := install.InstallPreCommit(repoRoot, ei.PluginDir(), opts); err != nil {
				fmt.Fprintf(os.Stderr, "  %s Pre-commit hook: %v\n", warnMark, err)
			} else {
				fmt.Fprintf(os.Stderr, "  %s Pre-commit hook installed\n", successMark)
			}
		} else {
			fmt.Fprintf(os.Stderr, "  %s Pre-commit hook: not inside a git repository\n", warnMark)
		}
	}

	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintf(os.Stderr, "  %s Setup complete.\n", successMark)
	fmt.Fprintln(os.Stderr, "")
	if accessible {
		fmt.Fprintln(os.Stderr, "  Next steps:")
		fmt.Fprintln(os.Stderr, "    Restart your editors to activate the MCP server.")
		if installPreCommit {
			fmt.Fprintln(os.Stderr, "    Run 'armis-cli hook init' in other repos for pre-commit coverage.")
		}
	} else {
		dimStyle := lipgloss.NewStyle().Foreground(brandMuted)
		fmt.Fprintln(os.Stderr, dimStyle.Render("  Next steps:"))
		fmt.Fprintln(os.Stderr, dimStyle.Render("    Restart your editors to activate the MCP server."))
		if installPreCommit {
			fmt.Fprintln(os.Stderr, dimStyle.Render("    Run 'armis-cli hook init' in other repos for pre-commit coverage."))
		}
	}
	fmt.Fprintln(os.Stderr, "")
	return nil
}

func collectCredentials(theme *huh.Theme, accessible bool) (clientID, clientSecret string, skip, aborted bool) {
	ei := install.NewEditorInstaller()
	envID := os.Getenv("ARMIS_CLIENT_ID")
	envSecret := os.Getenv("ARMIS_CLIENT_SECRET")

	// Auto-validate env vars without asking
	if envID != "" && envSecret != "" {
		if err := validateAndReport(envID, envSecret, accessible); err == nil {
			return envID, envSecret, false, false
		}
		// Invalid — fall through to prompt for new credentials
	}

	// Check if .env already exists
	if ei.HasExistingEnv() {
		keepExisting := true
		form := huh.NewForm(
			huh.NewGroup(
				huh.NewConfirm().
					Title("Existing credentials found. Keep them?").
					Affirmative("Yes").
					Negative("No, enter new ones").
					Value(&keepExisting),
			),
		).WithTheme(theme).WithAccessible(accessible)
		if err := form.Run(); err != nil {
			return "", "", false, errors.Is(err, huh.ErrUserAborted)
		}
		if keepExisting {
			return "", "", true, false
		}
	}

	// Prompt for credentials
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Client ID").
				Description("From Armis platform > Settings > API Credentials (Enter to skip)").
				Value(&clientID),
			huh.NewInput().
				Title("Client Secret").
				Description("Press Enter to skip and configure later").
				EchoMode(huh.EchoModePassword).
				Value(&clientSecret),
		),
	).WithTheme(theme).WithAccessible(accessible)

	if err := form.Run(); err != nil {
		return "", "", false, errors.Is(err, huh.ErrUserAborted)
	}

	if clientID == "" || clientSecret == "" {
		fmt.Fprintln(os.Stderr, "  Skipping credentials — configure later in the .env file.")
		return "", "", true, false
	}

	// Validate credentials
	if err := validateAndReport(clientID, clientSecret, accessible); err != nil {
		// Offer retry
		retry := true
		retryForm := huh.NewForm(
			huh.NewGroup(
				huh.NewConfirm().
					Title("Try again?").
					Affirmative("Yes").
					Negative("No, skip for now").
					Value(&retry),
			),
		).WithTheme(theme).WithAccessible(accessible)
		if retryErr := retryForm.Run(); retryErr != nil {
			if errors.Is(retryErr, huh.ErrUserAborted) {
				return "", "", false, true
			}
			fmt.Fprintln(os.Stderr, "  Skipping credentials — configure later in the .env file.")
			return "", "", true, false
		}
		if !retry {
			fmt.Fprintln(os.Stderr, "  Skipping credentials — configure later in the .env file.")
			return "", "", true, false
		}

		// Second attempt
		clientID = ""
		clientSecret = ""
		retryInputForm := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("Client ID").
					Value(&clientID),
				huh.NewInput().
					Title("Client Secret").
					EchoMode(huh.EchoModePassword).
					Value(&clientSecret),
			),
		).WithTheme(theme).WithAccessible(accessible)
		if err := retryInputForm.Run(); err != nil {
			return "", "", false, errors.Is(err, huh.ErrUserAborted)
		}
		if clientID == "" || clientSecret == "" {
			return "", "", true, false
		}
		if err := validateAndReport(clientID, clientSecret, accessible); err != nil {
			fmt.Fprintln(os.Stderr, "  Credential validation failed. Credentials were not saved — re-run the installer to try again.")
			return "", "", true, false
		}
	}

	return clientID, clientSecret, false, false
}

func validateAndReport(clientID, clientSecret string, accessible bool) error {
	fmt.Fprint(os.Stderr, "  Verifying credentials... ")
	if err := install.ValidateCredentials(clientID, clientSecret); err != nil {
		if accessible {
			fmt.Fprintln(os.Stderr, "[FAIL]")
		} else {
			fmt.Fprintln(os.Stderr, lipgloss.NewStyle().Foreground(brandError).Render("✗"))
		}
		for _, line := range strings.Split(err.Error(), "\n") {
			fmt.Fprintf(os.Stderr, "  %s\n", line)
		}
		fmt.Fprintln(os.Stderr, "")
		return err
	}
	if accessible {
		fmt.Fprintln(os.Stderr, "[OK]")
	} else {
		fmt.Fprintln(os.Stderr, lipgloss.NewStyle().Foreground(brandSuccess).Render("✓"))
	}
	fmt.Fprintln(os.Stderr, "")
	return nil
}

// selectEditorsResult holds the selection from the editor picker.
type selectEditorsResult struct {
	editors       []install.Editor
	installClaude bool
	installCodex  bool
	cancelled     bool
}

func selectEditorsWithCodex(theme *huh.Theme, accessible bool) selectEditorsResult {
	detected := install.DetectedEditors()

	claudeAvailable := false
	if _, err := install.NewClaudeInstaller(); err == nil {
		claudeAvailable = true
	}
	codexAvailable := install.IsCodexDetected()

	if len(detected) == 0 && !claudeAvailable && !codexAvailable {
		fmt.Fprintln(os.Stderr, "  No supported editors detected.")
		return selectEditorsResult{}
	}

	var options []huh.Option[string]
	var allEditorKeys []string

	for _, e := range detected {
		key := string(e.ID)
		options = append(options, huh.NewOption(e.Name, key))
		allEditorKeys = append(allEditorKeys, key)
	}
	if claudeAvailable {
		options = append(options, huh.NewOption("Claude Code", "claude"))
		allEditorKeys = append(allEditorKeys, "claude")
	}
	if codexAvailable {
		options = append(options, huh.NewOption("Codex CLI", targetCodex))
		allEditorKeys = append(allEditorKeys, targetCodex)
	}

	// Pre-select all by default
	selected := make([]string, len(allEditorKeys))
	copy(selected, allEditorKeys)

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewMultiSelect[string]().
				Title("Select editors to install").
				Options(options...).
				Value(&selected).
				Filterable(false),
		),
	).WithTheme(theme).WithAccessible(accessible)

	if err := form.Run(); err != nil {
		return selectEditorsResult{cancelled: true}
	}

	var editors []install.Editor
	installClaude := false
	installCodex := false

	for _, sel := range selected {
		switch sel {
		case "claude":
			installClaude = true
		case targetCodex:
			installCodex = true
		default:
			if e, ok := install.EditorByID(install.EditorID(sel)); ok {
				editors = append(editors, e)
			}
		}
	}

	return selectEditorsResult{
		editors:       editors,
		installClaude: installClaude,
		installCodex:  installCodex,
		cancelled:     false,
	}
}

func offerHookSetup(theme *huh.Theme, accessible bool, hasClaude bool) ([]install.HookClient, bool) {
	detected := install.DetectHookClients()

	// All covered when any AI tool with native hooks is present (Claude via plugin,
	// or detected clients that will be configured). Pre-commit is optional in that case.
	allCovered := hasClaude || len(detected) > 0

	// Build hook client options
	var hookOptions []huh.Option[string]
	var allHookKeys []string

	for _, hc := range detected {
		key := string(hc.ID)
		hookOptions = append(hookOptions, huh.NewOption(hc.Name, key))
		allHookKeys = append(allHookKeys, key)
	}

	// Pre-select all detected clients
	selectedHooks := make([]string, len(allHookKeys))
	copy(selectedHooks, allHookKeys)

	// Pre-commit: default ON if not all covered, OFF if all covered
	installPreCommit := !allCovered
	repoRoot := install.DetectGitRoot()
	inGitRepo := repoRoot != ""

	if !inGitRepo && len(hookOptions) == 0 {
		if !hasClaude {
			if accessible {
				fmt.Fprintln(os.Stderr, "  No hook-capable AI clients detected. Skipping hook setup.")
			} else {
				dimStyle := lipgloss.NewStyle().Foreground(brandMuted)
				fmt.Fprintln(os.Stderr, dimStyle.Render("  No hook-capable AI clients detected. Skipping hook setup."))
			}
		}
		return nil, false
	}

	var groups []*huh.Group

	if len(hookOptions) > 0 {
		hookDesc := "Select AI clients to configure security scanning hooks"
		if hasClaude {
			hookDesc += "\nClaude Code: already covered via plugin system"
		}
		groups = append(groups, huh.NewGroup(
			huh.NewMultiSelect[string]().
				Title("Security scanning hooks").
				Description(hookDesc).
				Options(hookOptions...).
				Value(&selectedHooks).
				Filterable(false),
		))
	}

	if inGitRepo {
		desc := "Verifies scan-pass before allowing commits."
		if allCovered {
			desc += " Optional — your AI tools already have native hooks."
		} else {
			desc += " Recommended — no AI tools with native hooks detected."
		}
		groups = append(groups, huh.NewGroup(
			huh.NewConfirm().
				Title("Install git pre-commit hook?").
				Description(desc).
				Affirmative("Yes").
				Negative("No").
				Value(&installPreCommit),
		))
	}

	if len(groups) == 0 {
		return nil, false
	}

	form := huh.NewForm(groups...).WithTheme(theme).WithAccessible(accessible)
	if err := form.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "\n  Skipping hook setup.")
		return nil, false
	}

	var result []install.HookClient
	for _, sel := range selectedHooks {
		if hc, ok := install.HookClientByID(install.HookClientID(sel)); ok {
			result = append(result, hc)
		}
	}

	return result, installPreCommit
}
