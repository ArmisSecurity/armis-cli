package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/supplychain"
	"github.com/spf13/cobra"
)

var (
	scInitMode   string
	scInitDryRun bool
	scInitYes    bool
)

var scInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Set up local package age enforcement",
	Long: `Configure your shell to enforce package release age policies during installations.

This wraps your package manager (auto-detected from lockfiles) so that armis-cli
can enforce age policies on package installations. Node PMs (npm, pnpm, bun, yarn)
use a transparent proxy that filters registry responses.

Four modes are available:
  rc     — Inject shell functions into ~/.bashrc / ~/.zshrc (default, interactive)
  env    — Print an eval command for CI or manual sourcing
  npmrc  — Write registry override to .npmrc (project-level)
  config — Generate .armis-supply-chain.yaml policy file for this project

Run 'armis-cli supply-chain uninit' to reverse changes made by this command.`,
	Example: `  # Interactive setup (default)
  armis-cli supply-chain init

  # See what would be modified
  armis-cli supply-chain init --dry-run

  # Non-interactive (CI friendly)
  armis-cli supply-chain init --yes

  # Print eval command for CI
  armis-cli supply-chain init --mode env

  # Write .npmrc override
  armis-cli supply-chain init --mode npmrc`,
	Args: cobra.NoArgs,
	RunE: runSupplyChainInit,
}

func init() {
	scInitCmd.Flags().StringVar(&scInitMode, "mode", "rc", "Setup mode: rc, env, npmrc, config")
	scInitCmd.Flags().BoolVar(&scInitDryRun, "dry-run", false, "Show what would be modified without making changes")
	scInitCmd.Flags().BoolVar(&scInitYes, "yes", false, "Skip confirmation prompt")

	_ = scInitCmd.RegisterFlagCompletionFunc("mode", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{"rc\tShell RC injection (default)", "env\tEval command for CI", "npmrc\tProject .npmrc", "config\tGenerate .armis-supply-chain.yaml"}, cobra.ShellCompDirectiveNoFileComp
	})

	supplyChainCmd.AddCommand(scInitCmd)
}

func runSupplyChainInit(_ *cobra.Command, _ []string) error {
	pms := detectWrappablePMs()

	switch scInitMode {
	case "env":
		return runInitEnv(pms)
	case "npmrc":
		return runInitNpmrc()
	case "rc":
		return runInitRC(pms)
	case "config":
		return runInitConfig()
	default:
		return fmt.Errorf("unknown mode: %s (valid: rc, env, npmrc, config)", scInitMode)
	}
}

func detectWrappablePMs() []string {
	ecosystems, err := supplychain.DetectEcosystems(".")
	if err != nil {
		// DetectEcosystems only errors when no supported lockfile is present.
		// Default to npm so the generated wrapper still protects the most common
		// package manager rather than silently wrapping nothing.
		return []string{pmNPM}
	}

	seen := make(map[string]bool)
	var pms []string

	for _, e := range ecosystems {
		pm := ecosystemToPM(e.Ecosystem)
		if pm == "" {
			continue
		}
		if !seen[pm] {
			seen[pm] = true
			pms = append(pms, pm)
		}
	}

	if len(pms) == 0 {
		return []string{pmNPM}
	}
	return pms
}

func ecosystemToPM(eco supplychain.Ecosystem) string {
	switch eco {
	case supplychain.EcosystemNPM:
		return pmNPM
	case supplychain.EcosystemPNPM:
		return pmPNPM
	case supplychain.EcosystemBun:
		return pmBun
	case supplychain.EcosystemYarn:
		return pmYarn
	default:
		return ""
	}
}

// promptYesNo prints an interactive yes/no prompt to stderr and reads the reply
// from stdin. See readYesNo for the answer semantics.
func promptYesNo(prompt string, defaultYes bool) bool {
	suffix := "[y/N]"
	if defaultYes {
		suffix = "[Y/n]"
	}
	fmt.Fprintf(os.Stderr, "%s %s ", prompt, suffix)
	return readYesNo(os.Stdin, defaultYes)
}

// readYesNo reads a single line from r and reports whether it is affirmative.
// An empty answer (the user pressing Enter) accepts the default. If the stream
// is closed or the read fails before any input is received, it returns false so
// callers fail closed — an unreadable prompt must never be treated as consent
// for a destructive action like editing shell RC files.
func readYesNo(r io.Reader, defaultYes bool) bool {
	line, err := bufio.NewReader(r).ReadString('\n')
	// ReadString returns any data read so far alongside io.EOF when input ends
	// without a trailing newline (e.g. "y"+Ctrl-D), so only fail closed when the
	// read produced nothing at all — that signals no interactive human present.
	// armis:ignore cwe:253 reason:the error IS handled — a read error with no data fails closed; a read error with partial data intentionally honors the data already entered
	if err != nil && line == "" {
		return false
	}

	answer := strings.TrimSpace(strings.ToLower(line))
	if answer == "" {
		return defaultYes
	}
	return answer == "y" || answer == "yes"
}

func runInitEnv(pms []string) error {
	s := output.GetStyles()
	// armis:ignore cwe:78 reason:EvalCommand runs every name through sanitizePMNames (^[a-z][a-z0-9-]*$) before interpolation, so no shell metacharacter can reach the generated eval string; pms originates from local lockfile detection regardless
	block := supplychain.EvalCommand(pms)
	if scInitDryRun {
		fmt.Fprintf(os.Stderr, "%s\n\n", s.MutedText.Render("Would print eval command:"))
	}
	fmt.Print(block)
	if !scInitDryRun {
		fmt.Fprintf(os.Stderr, "\n%s %s\n", s.MutedText.Render("Usage:"), s.Bold.Render("eval \"$(armis-cli supply-chain init --mode env)\""))
	}
	return nil
}

func runInitNpmrc() error {
	s := output.GetStyles()
	npmrcPath := ".npmrc"
	line := "# armis-cli supply-chain: registry override applied at install time via 'supply-chain wrap'\n"

	if scInitDryRun {
		fmt.Fprintf(os.Stderr, "%s\n", s.MutedText.Render(fmt.Sprintf("Would add comment to %s noting that supply-chain wrap handles registry override.", npmrcPath)))
		fmt.Fprintf(os.Stderr, "%s\n", s.MutedText.Render("Note: npmrc mode works with 'eval' mode — the registry URL is set dynamically by supply-chain wrap."))
		return nil
	}

	// armis:ignore cwe:770 cwe:22 cwe:23 cwe:73 reason:npmrcPath is the hardcoded literal ".npmrc" in the cwd; a bounded local project config file, not user/network input
	content, err := os.ReadFile(npmrcPath) //nolint:gosec // project .npmrc in current working directory
	if err != nil && !os.IsNotExist(err) {
		// A missing .npmrc is expected (we create it below); any other read error
		// (permissions, I/O) must surface rather than be silently treated as an
		// empty file, which would make the "already configured" check unreliable.
		return fmt.Errorf("reading %s: %w", npmrcPath, err)
	}
	if strings.Contains(string(content), "armis-cli supply-chain") {
		fmt.Fprintf(os.Stderr, "%s already contains armis-cli supply-chain configuration.\n", s.Bold.Render(npmrcPath))
		return nil
	}

	// O_APPEND writes at the current end of file without inserting a separator,
	// so if an existing .npmrc does not end in a newline (common for hand-edited
	// config) the comment would be concatenated onto the last entry — e.g.
	// "foo=bar" becomes "foo=bar# armis-cli ...", corrupting foo's value. Prepend
	// a newline when the file is non-empty and lacks a trailing one, mirroring
	// injectIntoFile in shell.go.
	if len(content) > 0 && !strings.HasSuffix(string(content), "\n") {
		line = "\n" + line
	}

	// armis:ignore cwe:732 cwe:73 cwe:22 cwe:23 reason:npmrcPath is the hardcoded literal ".npmrc" in the cwd, not user input; the file holds only a non-secret comment pointing at supply-chain wrap, so 0644 (respecting umask) is intentional for a project file
	f, err := os.OpenFile(npmrcPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644) //nolint:gosec // project .npmrc
	if err != nil {
		return fmt.Errorf("opening %s: %w", npmrcPath, err)
	}
	defer f.Close() //nolint:errcheck

	if _, err := f.WriteString(line); err != nil {
		return fmt.Errorf("writing %s: %w", npmrcPath, err)
	}

	fmt.Fprintf(os.Stderr, "%s Updated %s\n", s.SuccessText.Render(output.IconSuccess), s.Bold.Render(npmrcPath))
	fmt.Fprintf(os.Stderr, "%s %s\n", s.MutedText.Render("Use with:"), s.Bold.Render("eval \"$(armis-cli supply-chain init --mode env)\""))
	return nil
}

func runInitRC(pms []string) error {
	s := output.GetStyles()

	shells := supplychain.DetectShells()
	if len(shells) == 0 {
		return fmt.Errorf("no supported shells detected (bash, zsh, or fish)")
	}

	fmt.Fprintf(os.Stderr, "%s ", s.MutedText.Render("Detected shell(s):"))
	names := make([]string, 0, len(shells))
	for _, sh := range shells {
		names = append(names, s.Bold.Render(sh.Name)+" ("+sh.RCFile+")")
	}
	fmt.Fprintf(os.Stderr, "%s\n\n", strings.Join(names, ", "))

	// Preview each distinct wrapper. bash/zsh share the posix wrapper while fish
	// uses different syntax, so group shells by the wrapper they produce to keep
	// the preview accurate when multiple shells are detected.
	fmt.Fprintf(os.Stderr, "%s\n\n", s.SectionTitle.Render("Will inject the following into shell RC file(s):"))
	var order []string
	shellsByWrapper := make(map[string][]string)
	for _, sh := range shells {
		w := supplychain.GenerateWrapper(sh.Name, pms)
		if _, seen := shellsByWrapper[w]; !seen {
			order = append(order, w)
		}
		shellsByWrapper[w] = append(shellsByWrapper[w], sh.Name)
	}
	for _, w := range order {
		fmt.Fprintf(os.Stderr, "%s\n", s.MutedText.Render(strings.Join(shellsByWrapper[w], ", ")+":"))
		fmt.Fprintf(os.Stderr, "%s\n", s.CodeBlock.Render(w))
	}

	if scInitDryRun {
		fmt.Fprintf(os.Stderr, "%s\n", s.MutedText.Render("(dry-run: no changes made)"))
		return nil
	}

	if !scInitYes {
		if !promptYesNo(s.Bold.Render("Proceed?"), true) {
			fmt.Fprintf(os.Stderr, "Aborted.\n")
			return nil
		}
	}

	modified, err := supplychain.InjectFunctions(shells, pms)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "\n")
	for _, f := range modified {
		fmt.Fprintf(os.Stderr, "  %s Modified: %s\n", s.SuccessText.Render(output.IconSuccess), s.Bold.Render(f))
	}

	fmt.Fprintf(os.Stderr, "\n%s Restart your shell or run:\n", s.SuccessText.Render("Done!"))
	for _, sh := range shells {
		fmt.Fprintf(os.Stderr, "  %s\n", s.Bold.Render("source "+sh.RCFile))
	}
	policy := resolveWrapPolicy()
	fmt.Fprintf(os.Stderr, "\n%s block packages published less than %s ago\n", s.MutedText.Render("Policy:"), policy.MinReleaseAge)
	fmt.Fprintf(os.Stderr, "%s %s\n", s.MutedText.Render("Undo:  "), s.Bold.Render("armis-cli supply-chain uninit"))

	return nil
}

func runInitConfig() error {
	s := output.GetStyles()
	configPath := supplychain.ConfigFileName

	if _, err := os.Stat(configPath); err == nil {
		fmt.Fprintf(os.Stderr, "%s already exists.\n", s.Bold.Render(configPath))
		fmt.Fprintf(os.Stderr, "%s\n", s.MutedText.Render("Use --mode rc to set up shell enforcement instead."))
		return nil
	}

	ecosystems, _ := supplychain.DetectEcosystems(".")
	var ecoNames []string
	for _, e := range ecosystems {
		ecoNames = append(ecoNames, string(e.Ecosystem))
	}

	var exclusionsBlock string
	scopes := detectOrgScopes(ecosystems)
	if len(scopes) > 0 {
		var lines []string
		for _, scope := range scopes {
			lines = append(lines, fmt.Sprintf("  - %q", scope+"/*"))
		}
		exclusionsBlock = "exclusions:\n" + strings.Join(lines, "\n") + "\n"
	} else {
		exclusionsBlock = "# exclusions:\n#   - \"@myorg/*\"\n"
	}

	var ecoBlock string
	if len(ecoNames) > 0 {
		var lines []string
		for _, name := range ecoNames {
			lines = append(lines, "  - "+name)
		}
		ecoBlock = "ecosystems:\n" + strings.Join(lines, "\n") + "\n"
	} else {
		ecoBlock = "# ecosystems:\n#   - npm\n"
	}

	content := fmt.Sprintf(`# armis-cli supply-chain configuration
# Docs: armis-cli supply-chain --help
version: 1

# Minimum time since publication before a package version is allowed
min-age: 72h

# Packages matching these glob patterns bypass age checks
%s
# Which package ecosystems to enforce (auto-detected if omitted)
%s
# If true, allow installs when the registry is unreachable
fail-open: false
`, exclusionsBlock, ecoBlock)

	if scInitDryRun {
		fmt.Fprintf(os.Stderr, "%s\n\n", s.MutedText.Render(fmt.Sprintf("Would write %s:", configPath)))
		fmt.Fprintf(os.Stderr, "%s\n", content)
		fmt.Fprintf(os.Stderr, "%s\n", s.MutedText.Render("(dry-run: no changes made)"))
		return nil
	}

	if !scInitYes {
		fmt.Fprintf(os.Stderr, "%s\n\n", s.SectionTitle.Render(fmt.Sprintf("Will create %s:", configPath)))
		fmt.Fprintf(os.Stderr, "%s\n", s.CodeBlock.Render(content))
		if !promptYesNo(s.Bold.Render("Proceed?"), true) {
			fmt.Fprintf(os.Stderr, "Aborted.\n")
			return nil
		}
	}

	// armis:ignore cwe:732 reason:the supply-chain policy file is non-secret config explicitly intended to be committed and shared with the team; 0644 (respecting umask) is the correct mode for a world-readable project file
	if err := os.WriteFile(configPath, []byte(content), 0o644); err != nil { //nolint:gosec // project config file
		return fmt.Errorf("writing %s: %w", configPath, err)
	}

	fmt.Fprintf(os.Stderr, "%s Created %s\n", s.SuccessText.Render(output.IconSuccess), s.Bold.Render(configPath))
	fmt.Fprintf(os.Stderr, "%s\n", s.MutedText.Render("Commit this file to share policy with your team."))
	return nil
}

// maxDetectedScopes bounds how many distinct org scopes detectOrgScopes
// collects. The result only pre-populates suggested exclusions in the generated
// config, so there is no value in scanning the entire lockfile of a large
// monorepo once we already have a representative set.
const maxDetectedScopes = 16

func detectOrgScopes(ecosystems []supplychain.DetectedEcosystem) []string {
	seen := make(map[string]bool)
	var scopes []string
	for _, e := range ecosystems {
		if e.Ecosystem != supplychain.EcosystemNPM && e.Ecosystem != supplychain.EcosystemPNPM && e.Ecosystem != supplychain.EcosystemBun {
			continue
		}
		if collectScopesFromFile(e.LockfilePath, seen, &scopes) {
			break // hit the cap; no need to read remaining lockfiles
		}
	}
	return scopes
}

// collectScopesFromFile streams the lockfile line by line (rather than reading
// the whole file into memory) and appends any newly-seen org scopes. It returns
// true once maxDetectedScopes distinct scopes have been collected.
func collectScopesFromFile(path string, seen map[string]bool, scopes *[]string) bool {
	// armis:ignore cwe:22 cwe:73 reason:local CLI reading the user's own lockfile to suggest config exclusions; path comes from local lockfile detection, not untrusted input crossing a trust boundary
	f, err := os.Open(path) //nolint:gosec // lockfile path from local detection
	if err != nil {
		return false
	}
	defer f.Close() //nolint:errcheck

	sc := bufio.NewScanner(f)
	// Lockfile lines can be long (resolved URLs, integrity hashes); raise the
	// scanner's buffer so a single long line doesn't abort the scan.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		idx := strings.Index(line, "@")
		if idx < 0 {
			continue
		}
		scope := extractScope(line[idx:])
		if scope == "" || seen[scope] {
			continue
		}
		seen[scope] = true
		*scopes = append(*scopes, scope)
		if len(*scopes) >= maxDetectedScopes {
			return true
		}
	}
	return false
}

func extractScope(s string) string {
	if !strings.HasPrefix(s, "@") {
		return ""
	}
	end := strings.Index(s, "/")
	if end <= 1 {
		return ""
	}
	scope := s[:end]
	for _, c := range scope[1:] {
		// npm scope names allow lowercase and uppercase letters (uppercase is
		// legacy but still valid), digits, and -_. characters.
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' && c != '.' {
			return ""
		}
	}
	return scope
}
