package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/cmd/cmdutil"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/supplychain"
	"github.com/charmbracelet/huh"
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

This wraps every supported package manager found on your PATH so that armis-cli
can enforce age policies on package installations. The shell functions are global
(they apply in every directory), so init wraps what is installed on the machine,
not just what a single project uses; whether enforcement actually runs is decided
per-project at install time from the nearest .armis-supply-chain.yaml. Node PMs
(npm, npx, pnpm, bun, yarn) and pip/uv/uvx use a transparent proxy that filters
registry responses. poetry, pipenv, pdm, mvn, and gradle use a pre-install check
that blocks the build if violations are found.

Four modes are available:
  rc     — Inject shell functions into ~/.bashrc / ~/.zshrc / fish config /
           PowerShell profile (default, interactive)
  env    — Print an eval command for CI or manual sourcing
  npmrc  — Add a marker comment to .npmrc (the registry override itself is set
           dynamically by 'supply-chain wrap'; use with the rc or env modes)
  config — Generate .armis-supply-chain.yaml policy file for this project

Run 'armis-cli supply-chain uninit' to reverse the shell RC and .npmrc changes
made by this command. The --mode config policy file (.armis-supply-chain.yaml) is
meant to be committed and shared with your team, so uninit leaves it in place;
remove it manually if you no longer want it.`,
	Example: `  # Interactive setup (default)
  armis-cli supply-chain init

  # See what would be modified
  armis-cli supply-chain init --dry-run

  # Non-interactive (CI friendly)
  armis-cli supply-chain init --yes

  # Print eval command for CI
  armis-cli supply-chain init --mode env

  # Add the supply-chain marker comment to .npmrc
  armis-cli supply-chain init --mode npmrc

  # Generate a committable .armis-supply-chain.yaml for this project
  armis-cli supply-chain init --mode config`,
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
	switch scInitMode {
	case "npmrc":
		// npmrc only adds a marker comment; it doesn't wrap package managers, so
		// it never consults the detected/scoped PM list.
		return runInitNpmrc()
	case "config":
		// config generates the policy file itself; ecosystem scoping doesn't apply
		// until that file exists, so it also skips PM detection.
		return runInitConfig()
	case "env", "rc":
		pms, installed := detectWrappablePMs()
		if len(pms) == 0 {
			// Package managers were found on PATH, but the config's `ecosystems`
			// scope excludes every one — there is nothing in scope to wrap. Report
			// it plainly instead of falling back to npm: wrapping an ecosystem the
			// user deliberately scoped enforcement away from would modify their RC
			// files (rc) or emit an eval they didn't ask for (env), contradicting
			// init's stated "only wraps in-scope package managers" behavior.
			return reportNothingInScope(installed)
		}
		if scInitMode == "rc" {
			return runInitRC(pms)
		}
		return runInitEnv(pms)
	default:
		return fmt.Errorf("unknown mode: %s (valid: rc, env, npmrc, config)", scInitMode)
	}
}

// reportNothingInScope explains that package managers were found on PATH but the
// config's `ecosystems` scope excludes all of them, so init has nothing to set
// up. It returns nil (not an error): scoping enforcement away from every
// installed ecosystem is a legitimate user choice, so exiting 0 with guidance is
// the correct, CI-friendly outcome. installed is the raw list of PM command
// names found on PATH (e.g. ["npm", "pip3"]).
func reportNothingInScope(installed []string) error {
	s := output.GetStyles()

	fmt.Fprintf(os.Stderr, "%s No package managers in scope to wrap.\n\n", s.WarningText.Render("⚠"))
	fmt.Fprintf(os.Stderr, "%s\n", s.MutedText.Render(fmt.Sprintf(
		"Found %s on PATH, but the `ecosystems` scope in %s excludes all of them.",
		strings.Join(installed, ", "), supplychain.ConfigFileName)))
	fmt.Fprintf(os.Stderr, "%s\n", s.MutedText.Render(
		"Add one of them to that list (or remove the `ecosystems` key to enforce all) to set up enforcement."))
	return nil
}

// allSupportedPMs is the set of fixed package-manager command names init looks
// for on PATH. pip is intentionally omitted: its variants (pip, pip3, pip3.12)
// are matched by pattern inside DetectInstalledPMs, since each interpreter ships
// its own pip binary. npx and uvx are omitted too — they are not detected
// directly but paired with npm/uv below, mirroring how the wrap gate treats them
// as part of the npm/uv ecosystem.
var allSupportedPMs = []string{
	pmNPM, pmPNPM, pmBun, pmYarn,
	pmUV, pmPoetry, pmPipenv, pmPDM,
	pmMaven, pmGradle,
}

// detectWrappablePMs returns the package managers init should wrap, plus the raw
// list of package-manager commands found on PATH. Detection is PATH-based, not
// lockfile-based: the shell functions init injects are global (they shadow the
// command in every directory), so the wrapper set should reflect what is
// installed on the machine rather than which lockfiles happen to sit in the
// current directory. Per-project enforcement is still decided dynamically at wrap
// time from the nearest config and policy.
//
// The two return values let the caller tell apart two cases that both yield an
// empty PM list:
//
//   - Nothing installed (installed is empty): no supported PM is on PATH, so we
//     fall back to npm (and its runner npx) and the returned PM slice is
//     non-empty.
//   - PMs installed but all scoped out (installed is non-empty, PM slice empty):
//     the config's `ecosystems` key excludes every installed ecosystem. The
//     caller reports this instead of wrapping something out of scope.
func detectWrappablePMs() (pms []string, installed []string) {
	installed = supplychain.DetectInstalledPMs(allSupportedPMs)
	if len(installed) == 0 {
		// No supported package manager is on PATH. Default to npm (and its runner
		// npx) so the generated wrapper still protects the most common package
		// manager rather than silently wrapping nothing — and so a one-off
		// `npx <pkg>` in a machine where npm was not on the scanned PATH (e.g. a
		// minimal CI image generating an eval block) is still guarded. installed
		// stays empty, signaling "nothing found" rather than "scoped out".
		return []string{pmNPM, pmNPX}, nil
	}

	// Honor the config's "ecosystems" scope so init only wraps the package
	// managers the user opted to enforce. Loaded best-effort from the current
	// directory upward: a nil config (none found, or load error) enforces
	// everything, matching the check/wrap gates.
	var cfg *supplychain.Config
	if dir := supplychain.FindConfigDir("."); dir != "" {
		cfg, _ = supplychain.LoadConfig(dir)
	}

	seen := make(map[string]bool)

	addPM := func(pm string) {
		if pm == "" || seen[pm] {
			return
		}
		seen[pm] = true
		pms = append(pms, pm)
	}

	for _, pm := range installed {
		// Map each command back to its ecosystem so the config scope applies. pip
		// variants (pip3, pip3.12) canonicalize to the pip ecosystem; an unknown
		// name (shouldn't happen — installed comes from our own scan) maps to "" and
		// is enforced by default.
		eco := pmToEcosystem(canonicalPM(pm))
		// armis:ignore cwe:476 reason:EnforcesEcosystem has an explicit nil-receiver guard (returns true when c==nil), so calling it on a nil cfg is safe by design
		if eco != "" && !cfg.EnforcesEcosystem(eco) {
			continue
		}
		addPM(pm)
	}

	// npx ships with npm and resolves from the same registry, so wherever npm is
	// wrapped its runner should be too: `npx <pkg>` downloads and executes a
	// package on demand, exactly the supply-chain vector the proxy guards. Pair it
	// here (after scoping) so it inherits npm's in-scope decision — when npm was
	// excluded by the `ecosystems` config it stays out, keeping the two in lockstep.
	// Guard with a PATH check: if npx is not installed, wrapping it would shadow
	// "command not found" with an Armis wrapper error. Use IsOnPath (single
	// exec.LookPath call) rather than DetectInstalledPMs which also enumerates
	// pip variants — unnecessary overhead for a single fixed-name check.
	if seen[pmNPM] && supplychain.IsOnPath(pmNPX) {
		addPM(pmNPX)
	}

	// uvx is uv's on-demand tool runner (`uvx X` ≡ `uv tool run X`), the PyPI
	// analogue of npx: it fetches a tool from PyPI and runs it, so wherever uv is
	// wrapped its runner should be too. Pair it after scoping so it inherits uv's
	// in-scope decision, and guard with a PATH check so a missing uvx binary is
	// never shadowed by an Armis wrapper error. Mirrors the npx pairing above.
	if seen[pmUV] && supplychain.IsOnPath(pmUVX) {
		addPM(pmUVX)
	}

	// An empty pms here means every installed PM was scoped out. We deliberately do
	// NOT fall back to npm: the caller uses the non-empty `installed` list to report
	// that nothing is in scope, rather than wrapping a package manager the user
	// asked enforcement to skip.
	return pms, installed
}

// summarizeDetectedPMs renders the wrapped package managers as a compact,
// human-readable summary for the init preview. It exists to answer the obvious
// question the raw wrapper block raises — "were these detected, or did init just
// add everything it supports?" — by surfacing exactly what was found on PATH:
//
//   - pip's interpreter-specific variants (pip3, pip3.11, pip3.12, …) collapse
//     into a single "pip (N variants)" entry. A multi-Python machine can expose a
//     dozen of these; listing each by name would bury the summary even though they
//     all resolve to PyPI and share one policy. The verbatim wrapper block below
//     still names every variant, so no information is lost — this is the digest.
//   - npx is annotated "(paired with npm)" and uvx "(paired with uv)" rather than
//     listed as plain finds, because neither is part of the primary detection set
//     (allSupportedPMs omits both). Each is paired with its base PM — and wrapped
//     only when confirmed present on PATH via the IsOnPath guards in
//     detectWrappablePMs — rather than being scanned for independently. The
//     annotation tells the user these came along with their base PM (npm/uv), so
//     the summary stays honest about which entries the main scan surfaced vs.
//     which the pairing logic added.
//
// Remaining names are shown as-is, bolded, in sorted order so the line is stable
// regardless of PATH scan order or where npx/uvx were appended.
func summarizeDetectedPMs(s *output.Styles, pms []string) string {
	var others []string
	pipVariants := 0
	hasNPX := false
	hasUVX := false

	for _, pm := range pms {
		switch {
		case pm == pmNPX:
			hasNPX = true
		case pm == pmUVX:
			hasUVX = true
		case supplychain.IsPipVariant(pm):
			pipVariants++
		default:
			others = append(others, pm)
		}
	}
	sort.Strings(others)

	parts := make([]string, 0, len(others)+3)
	for _, pm := range others {
		parts = append(parts, s.Bold.Render(pm))
	}
	if pipVariants > 0 {
		label := s.Bold.Render(pmPip)
		// Only flag the variant count when there is more than one binary; a lone
		// "pip" needs no "(1 variant)" noise.
		if pipVariants > 1 {
			label += s.MutedText.Render(fmt.Sprintf(" (%d variants)", pipVariants))
		}
		parts = append(parts, label)
	}
	if hasNPX {
		parts = append(parts, s.Bold.Render(pmNPX)+s.MutedText.Render(" (paired with npm)"))
	}
	if hasUVX {
		parts = append(parts, s.Bold.Render(pmUVX)+s.MutedText.Render(" (paired with uv)"))
	}

	// Keep pip and the paired runners (npx, uvx) at the end of the line: pip carries
	// a parenthetical and the runners are inferred entries, so trailing them reads
	// more naturally than interleaving by alphabetical position.
	return strings.Join(parts, ", ")
}

// powerShellSkippedDottedPMs returns the package-manager names in pms that a
// PowerShell wrapper cannot define, because PowerShell function names may not
// contain a dot (e.g. pip3.12). It returns nil unless at least one detected
// shell is PowerShell — the limitation only matters when a PowerShell wrapper is
// actually being written, and on a bash/zsh/fish-only machine the dotted variant
// is wrapped normally. The init flow uses this to print a one-line note so a
// PowerShell user understands pip3.12 was skipped while pip and pip3 still cover
// the common case (the runtime canonicalizes every pip variant to PyPI anyway).
func powerShellSkippedDottedPMs(pms []string, shells []supplychain.Shell) []string {
	hasPowerShell := false
	for _, sh := range shells {
		if supplychain.IsPowerShell(sh.Name) {
			hasPowerShell = true
			break
		}
	}
	if !hasPowerShell {
		return nil
	}

	var dotted []string
	for _, pm := range pms {
		if strings.Contains(pm, ".") {
			dotted = append(dotted, pm)
		}
	}
	return dotted
}

// promptYesNo asks the user a yes/no question and reports their answer.
//
// On an interactive terminal it renders a themed huh.Confirm, matching the
// install flow (see install_interactive.go) so the whole CLI shares one look.
// huh requires a TTY, so when stdin/stderr is piped or redirected — CI, a
// here-doc, `echo y | ...` — it falls back to the plain readYesNo line reader,
// which preserves piped-stdin support and fail-closed semantics for the RC-file
// edits this prompt gates.
func promptYesNo(prompt string, defaultYes bool) bool {
	// Blank line separates the confirmation from the preview above it (the code
	// block / config snippet) so the prompt does not butt against the last line.
	fmt.Fprintln(os.Stderr)

	if cli.IsInteractive() {
		return confirmInteractive(prompt, defaultYes)
	}

	suffix := "[y/N]"
	if defaultYes {
		suffix = "[Y/n]"
	}
	fmt.Fprintf(os.Stderr, "%s %s ", output.GetStyles().Bold.Render(prompt), suffix)
	return readYesNo(os.Stdin, defaultYes)
}

// confirmInteractive renders a themed huh confirmation. A form error (including
// Ctrl-C / huh.ErrUserAborted) declines the action, mirroring readYesNo's
// fail-closed behavior so an interrupted prompt never edits the user's files.
func confirmInteractive(prompt string, defaultYes bool) bool {
	confirmed := defaultYes
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title(prompt).
				Affirmative("Yes").
				Negative("No").
				Value(&confirmed),
		),
	).WithTheme(cmdutil.GetInstallTheme()).WithAccessible(!cli.ColorsEnabled())

	if err := form.Run(); err != nil {
		return false
	}
	return confirmed
}

// maxPromptInput bounds how much of stdin a single yes/no prompt will read. A
// real answer is a few bytes; the cap stops a huge piped stream (e.g. a file
// redirected into stdin) from forcing an unbounded allocation (CWE-770). 4KB is
// far beyond any legitimate reply yet still reads a full line in normal use.
const maxPromptInput = 4 * 1024

// readYesNo reads a single line from r and reports whether it is affirmative.
// An empty answer (the user pressing Enter) accepts the default. If the stream
// is closed or the read fails before any input is received, it returns false so
// callers fail closed — an unreadable prompt must never be treated as consent
// for a destructive action like editing shell RC files.
func readYesNo(r io.Reader, defaultYes bool) bool {
	// Bound the read so an oversized stdin cannot exhaust memory; a yes/no reply
	// never approaches the limit, and a line longer than it simply gets truncated
	// before the trailing newline, which TrimSpace+comparison handles correctly.
	line, err := bufio.NewReader(io.LimitReader(r, maxPromptInput)).ReadString('\n')
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
	npmrcPath := supplychain.NpmrcFileName
	line := supplychain.NpmrcMarkerComment + "\n"

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
	if supplychain.HasNpmrcMarker(content) {
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
		return fmt.Errorf("no supported shells detected (bash, zsh, fish, or PowerShell)")
	}

	// Short-circuit: if every detected shell already has the exact wrapper we
	// would inject (same binary path, same PM set), nothing needs to change.
	if !scInitDryRun {
		alreadyDone := true
		for _, sh := range shells {
			if !supplychain.HasCurrentInjection(sh.RCFile, sh.Name, pms) {
				alreadyDone = false
				break
			}
		}
		if alreadyDone {
			fmt.Fprintf(os.Stderr, "%s Supply chain wrappers already configured — nothing to do.\n", s.SuccessText.Render(output.IconSuccess))
			fmt.Fprintf(os.Stderr, "%s %s\n", s.MutedText.Render("Undo:  "), s.Bold.Render("armis-cli supply-chain uninit"))
			return nil
		}
	}

	fmt.Fprintf(os.Stderr, "%s ", s.MutedText.Render("Detected shell(s):"))
	names := make([]string, 0, len(shells))
	for _, sh := range shells {
		names = append(names, s.Bold.Render(sh.Name)+" ("+sh.RCFile+")")
	}
	fmt.Fprintf(os.Stderr, "%s\n", strings.Join(names, ", "))

	// Mirror the shell line with a package-manager line so the user can see what
	// init found on their PATH before the wrapper preview, rather than inferring it
	// from the function block. This is the answer to "did we detect these or just
	// add everything we support?": only PMs actually on PATH appear, npx is marked
	// as paired (it ships with npm; it is not detected), and pip's interpreter
	// variants are folded into one entry so a multi-Python machine does not bury
	// the summary under a dozen near-identical names.
	fmt.Fprintf(os.Stderr, "%s %s\n\n",
		s.MutedText.Render("Package manager(s) to wrap:"), summarizeDetectedPMs(s, pms))

	// PowerShell cannot define functions whose name contains a dot, so a versioned
	// pip variant (pip3.12) is skipped in the PowerShell profile. Surface that as a
	// single muted line — only when a PowerShell shell is among those detected and a
	// dotted variant is actually present — so the user knows the skip is intentional
	// and that pip/pip3 still cover the common case.
	if dotted := powerShellSkippedDottedPMs(pms, shells); len(dotted) > 0 {
		var nonDottedPip []string
		for _, pm := range pms {
			if (pm == "pip" || pm == "pip3") && !strings.Contains(pm, ".") {
				nonDottedPip = append(nonDottedPip, pm)
			}
		}
		var suffix string
		if len(nonDottedPip) > 0 {
			suffix = fmt.Sprintf("; %s are wrapped instead", strings.Join(nonDottedPip, " and "))
		}
		fmt.Fprintf(os.Stderr, "%s\n\n", s.MutedText.Render(fmt.Sprintf(
			"Note: %s can't be wrapped in PowerShell (dotted function names are unsupported)%s.",
			strings.Join(dotted, ", "), suffix)))
	}

	// Preview each distinct wrapper. bash/zsh share the posix wrapper while fish
	// uses different syntax, so group shells by the wrapper they produce to keep
	// the preview accurate when multiple shells are detected.
	fmt.Fprintf(os.Stderr, "%s\n\n", s.SectionTitle.Render("Will inject the following into shell RC file(s):"))
	var order []string
	shellsByWrapper := make(map[string][]string)
	for _, sh := range shells {
		// armis:ignore cwe:78 cwe:77 reason:pms flows through sanitizePMNames inside GenerateWrapper (^[a-z][a-z0-9-]*(\.[0-9]+)?$), so no shell metacharacter can reach the generated wrapper string
		w := supplychain.GenerateWrapper(sh.Name, pms)
		if _, seen := shellsByWrapper[w]; !seen {
			order = append(order, w)
		}
		shellsByWrapper[w] = append(shellsByWrapper[w], sh.Name)
	}
	for _, w := range order {
		fmt.Fprintf(os.Stderr, "%s\n", s.MutedText.Render(strings.Join(shellsByWrapper[w], ", ")+":"))
		fmt.Fprintf(os.Stderr, "%s\n", s.RenderCodeBlock(w))
	}

	if scInitDryRun {
		fmt.Fprintf(os.Stderr, "%s\n", s.MutedText.Render("(dry-run: no changes made)"))
		return nil
	}

	if !scInitYes {
		if !promptYesNo("Proceed?", true) {
			fmt.Fprintf(os.Stderr, "Aborted.\n")
			return nil
		}
	}

	// armis:ignore cwe:78 cwe:77 reason:pms flows through sanitizePMNames inside InjectFunctions/GenerateWrapper (^[a-z][a-z0-9-]*(\.[0-9]+)?$), so no shell metacharacter can reach the generated wrapper or RC file
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
		fmt.Fprintf(os.Stderr, "  %s\n", s.Bold.Render(supplychain.ShellReloadCommand(sh.Name, sh.RCFile)))
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

	content := fmt.Sprintf(`# armis-cli supply-chain configuration
# Docs: armis-cli supply-chain --help
version: 1

# Minimum time since publication before a package version is allowed
min-age: 72h

# Packages matching these glob patterns bypass age checks
%s
# Restrict enforcement to specific ecosystems (default: all detected).
# Supported: npm, pnpm, bun, yarn, pip, poetry, pipenv, pdm, uv, maven, gradle
# NOTE: if you set "ecosystems" below, any "registries" entry for an excluded
# ecosystem is ignored — scoping enforcement out also scopes out its routing.
# ecosystems:
#   - npm
#   - pip

# Approved corporate registry per ecosystem (Nexus / JFrog Artifactory).
# When set, wrapped installs route through this registry (with your existing
# credentials forwarded) and CI 'check' flags packages resolved elsewhere.
#   - npm:  the npm group/proxy repo URL.
#   - pypi: the PyPI index URL — it MUST end in /simple/ (PEP 503).
# Credentials are read from your NATIVE config, never from this file:
#   - npm:  .npmrc  //host/path/:_authToken=...   (use _authToken, NOT _auth;
#           the legacy base64 _auth form is not supported in this version)
#   - pip:  the userinfo embedded in your index-url (https://user:token@host/...)
# registries:
#   npm: https://nexus.corp/repository/npm-group/
#   pypi: https://nexus.corp/repository/pypi-group/simple/

# Routing enforcement posture. Only "warn" is supported in this version:
# it prints a one-time notice when your effective registry is explicitly
# off-policy. ("block" is rejected at load time — it is not yet implemented,
# and silently downgrading it would give a false sense of enforcement.)
# registry-enforcement: warn

# Optional CA bundle (PEM) for the proxy's TLS connection to the registry, for
# a Nexus fronted by a corporate/private CA. Overridable via ARMIS_REGISTRY_CA_BUNDLE.
# registry-ca-bundle: /etc/ssl/corp-ca.pem

# If true, allow installs when the registry is unreachable
fail-open: false
`, exclusionsBlock)

	if scInitDryRun {
		fmt.Fprintf(os.Stderr, "%s\n\n", s.MutedText.Render(fmt.Sprintf("Would write %s:", configPath)))
		fmt.Fprintf(os.Stderr, "%s\n", content)
		fmt.Fprintf(os.Stderr, "%s\n", s.MutedText.Render("(dry-run: no changes made)"))
		return nil
	}

	if !scInitYes {
		fmt.Fprintf(os.Stderr, "%s\n\n", s.SectionTitle.Render(fmt.Sprintf("Will create %s:", configPath)))
		fmt.Fprintf(os.Stderr, "%s\n", s.RenderCodeBlock(content))
		if !promptYesNo("Proceed?", true) {
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
