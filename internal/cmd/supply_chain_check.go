package cmd

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/cmd/cmdutil"
	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/supplychain"
	"github.com/ArmisSecurity/armis-cli/internal/supplychain/check"
	"github.com/spf13/cobra"
)

// baseDetectGitTimeout bounds the git subprocesses used to fetch the base
// lockfile. git base detection only reads local objects, but a misconfigured
// remote or filesystem can wedge a git invocation indefinitely; this ceiling
// keeps `supply-chain check` from hanging on it. The parent command context is
// still honored, so SIGINT cancels sooner than this.
const baseDetectGitTimeout = 15 * time.Second

var (
	scMinAge       string
	scExclude      []string
	scBaseLockfile string
	scLockfile     string
	scAll          bool
	scFailOpen     bool
	scReport       string
	scFailOn       []string
)

var scCheckCmd = &cobra.Command{
	Use:   "check [path]",
	Short: "Audit lockfile for recently-published packages",
	Long: `Check your lockfile for packages that were published too recently.

By default, checks only packages that are new compared to the base branch lockfile.
In a git repository, the base lockfile is auto-detected from origin/main (or
origin/master). Use --base-lockfile to specify explicitly, or --all to check all
packages regardless.

This command queries the public package registry for publish dates. No Armis Cloud
authentication is required.`,
	Example: `  # Check current directory (auto-detects lockfile)
  armis-cli supply-chain check

  # Check with custom policy
  armis-cli supply-chain check --min-age 7d --exclude "@myorg/*"

  # Check all packages (not just new ones)
  armis-cli supply-chain check --all

  # CI usage with SARIF output
  armis-cli supply-chain check --format sarif --fail-on high

  # Fail gracefully if registry is unreachable
  armis-cli supply-chain check --fail-open`,
	Args: cobra.MaximumNArgs(1),
	RunE: runSupplyChainCheck,
}

func init() {
	scCheckCmd.Flags().StringVar(&scMinAge, "min-age", "72h", "Minimum release age threshold (e.g., 72h, 3d, 1w)")
	scCheckCmd.Flags().StringSliceVar(&scExclude, "exclude", nil, "Package patterns to exclude (glob syntax, e.g., @myorg/*)")
	scCheckCmd.Flags().StringVar(&scBaseLockfile, "base-lockfile", "", "Base lockfile to diff against (only report new packages)")
	scCheckCmd.Flags().StringVar(&scLockfile, "lockfile", "", "Explicit lockfile path (overrides auto-detection)")
	scCheckCmd.Flags().BoolVar(&scAll, "all", false, "Check all packages (disable auto-diff against base branch)")
	scCheckCmd.Flags().BoolVar(&scFailOpen, "fail-open", false, "Exit 0 on registry errors (fail-open for CI availability)")
	// --format and --exit-code are persistent flags on scanCmd, but supply-chain
	// is a sibling of scan in the command tree and does not inherit them.
	// runSupplyChainCheck consumes both (the format/exitCode globals), so register
	// them locally to match the scan commands. Defaults mirror the former root
	// registrations exactly. --fail-on is also registered locally below, but bound
	// to its own scFailOn var with a "medium" default (see that registration).
	scCheckCmd.Flags().StringVarP(&format, "format", "f", getEnvOrDefault("ARMIS_FORMAT", "human"), "Output format: human, json, sarif, junit")
	scCheckCmd.Flags().IntVar(&exitCode, "exit-code", 1, "Exit code when --fail-on triggers")
	// Locally shadow the root's persistent --fail-on with a default that can
	// actually gate. supply-chain violations are graded MEDIUM or HIGH by
	// ClassifySeverity (they never reach CRITICAL), so the root default of
	// [CRITICAL] (root.go) would let a copy-pasted `supply-chain check` pass CI
	// no matter how many violations it found — a silently broken gate. Default to
	// "medium" here so any real violation fails by default, while leaving the flag
	// fully overridable (e.g. --fail-on high to gate only on packages published
	// in the last 24h). Same sibling-of-scan rationale as --output below:
	// supply-chain does not inherit scan's flag defaults, and a locally-registered
	// flag cleanly shadows the root's persistent one (cobra's mergePersistentFlags
	// skips the parent flag when a same-named local flag exists). Bound to its own
	// scFailOn var — not the failOn global — so the two registrations don't both
	// write the global at init() time, where the resting default would silently
	// depend on init() ordering. runSupplyChainCheck reads scFailOn explicitly.
	// Registered before the completion func below, which keys off the flag pointer.
	scCheckCmd.Flags().StringSliceVar(&scFailOn, "fail-on", []string{"medium"}, "Exit with error on findings at these severity levels: INFO, LOW, MEDIUM, HIGH, CRITICAL")
	// These are distinct flag instances from scanCmd's, so the completion funcs
	// must be registered here too (Cobra keys completions by flag pointer).
	_ = scCheckCmd.RegisterFlagCompletionFunc("format", formatCompletions())
	_ = scCheckCmd.RegisterFlagCompletionFunc("fail-on", failOnCompletions())
	// --report writes the machine-readable supply-chain compliance report (the
	// audit trail security teams gate CI on). check parses flags normally, so a
	// flag is fine here — unlike `wrap`, which forwards every flag to the PM and
	// must use the ARMIS_SUPPLY_CHAIN_REPORT env var instead. "-" writes to stderr.
	// armis:ignore cwe:73 cwe:22 reason:scReport is a user-controlled CLI flag naming a file on their own machine where the audit document is written (same trust model as --output); no trust boundary is crossed
	scCheckCmd.Flags().StringVar(&scReport, "report", "", "Write supply-chain compliance report to file (JSON; '-' for stderr)")
	// --output is a persistent flag on scanCmd, but supply-chain is a sibling of
	// scan in the command tree and does not inherit it. Register it locally so
	// `supply-chain check` matches the scan commands: ResolveOutput already
	// consumes outputFile (file writing, extension-based format auto-detection,
	// color disabling). -o has no shorthand conflict in the supply-chain subtree.
	// armis:ignore cwe:73 cwe:22 reason:outputFile is the user-controlled --output CLI flag naming a file on their own machine (same pattern as scan's --output, suppressed at the ResolveOutput/NewFileOutput sink); no trust boundary is crossed
	scCheckCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write output to file (auto-detects format from extension: .json, .sarif, .xml)")

	supplyChainCmd.AddCommand(scCheckCmd)
}

func runSupplyChainCheck(cmd *cobra.Command, args []string) error {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}

	// Validate --fail-on up front, before lockfile detection and the registry
	// scan. supply-chain is a sibling of `scan` in the command tree, so it does
	// not inherit scan.PersistentPreRunE's validation; without this, a typo'd
	// --fail-on would run the full check and print results before erroring.
	// cmdutil.GetFailOn also case-normalizes to uppercase so ShouldFail (which
	// matches exactly) trips on a lowercase "medium". Read scFailOn (the
	// check-local flag, default "medium"), not the failOn global — scFailOn
	// shadows root's persistent --fail-on, whose [CRITICAL] default would never
	// gate a MEDIUM/HIGH supply-chain violation; see its registration.
	failOnSeverities, err := cmdutil.GetFailOn(scFailOn)
	if err != nil {
		return err
	}

	policy, err := resolvePolicy(cmd, dir)
	if err != nil {
		return err
	}

	lockfilePath := scLockfile
	if lockfilePath == "" {
		ecosystems, err := supplychain.DetectEcosystems(dir)
		if err != nil {
			return err
		}
		if len(ecosystems) == 0 {
			return fmt.Errorf("no lockfile detected in %s", dir)
		}
		lockfilePath = ecosystems[0].LockfilePath
	}

	// armis:ignore cwe:22 cwe:23 cwe:73 reason:local CLI auditing the user's own project; lockfilePath comes from lockfile auto-detection or an explicit --lockfile flag the user controls (e.g. "--lockfile ../sibling/package-lock.json"), not untrusted input crossing a trust boundary
	if _, err := os.Stat(lockfilePath); err != nil {
		return fmt.Errorf("lockfile not found: %s", lockfilePath) // armis:ignore cwe:22 cwe:23 cwe:73 reason:scanner attributes the lockfilePath finding to this line; lockfilePath is user-controlled CLI input for the user's own project, not untrusted input crossing a trust boundary
	}

	// The wrap's residue sweep can only remove the proxy origin of the run that
	// just finished; a wrapper killed mid-install leaves a stale loopback origin
	// behind, and versions before the sweep existed left residue routinely. Flag
	// any loopback registry reference so CI catches a corrupted lockfile before
	// it breaks builds that resolve outside the wrapper.
	if host, found := supplychain.DetectLoopbackRegistry(lockfilePath); found {
		cli.PrintWarningf("%s references a loopback registry (%s). If this is residue from an interrupted or pre-fix wrapped install, re-resolve against the real registry (e.g. ARMIS_SUPPLY_CHAIN=off <pm> install) or restore the lockfile from version control. If you intentionally use a local registry, ignore this warning.", lockfilePath, host)
	}

	// Respect the config's "ecosystems" scope: if it restricts enforcement and
	// this lockfile's ecosystem is excluded, skip the audit and report a clean
	// pass rather than checking an out-of-scope ecosystem. loadConfigUpward
	// returns nil (enforce-all) when no config is present, and EnforcesEcosystem
	// fails safe on an all-typo list.
	cfg, _, err := loadConfigUpward(dir)
	if err != nil {
		return err
	}
	eco := check.DetectEcosystemFromPath(lockfilePath)
	// armis:ignore cwe:476 reason:EnforcesEcosystem has an explicit nil-receiver guard (returns true when c==nil), so calling it on a nil cfg is safe by design
	if !cfg.EnforcesEcosystem(eco) {
		s := output.GetStyles()
		fmt.Fprintf(os.Stderr, "%s %s\n",
			s.MutedText.Render("[armis]"),
			s.MutedText.Render(fmt.Sprintf("supply-chain: %s not in configured ecosystems, skipping", eco)))
		return nil
	}

	var baseLockfile string
	var autoDetectedBase bool
	if !scAll {
		if scBaseLockfile != "" {
			baseLockfile = scBaseLockfile
		} else {
			baseLockfile = detectBaseLockfile(cmd.Context(), lockfilePath)
			autoDetectedBase = baseLockfile != ""
		}
	}
	if autoDetectedBase {
		// armis:ignore cwe:73 cwe:22 reason:this branch only runs when autoDetectedBase is set, which detectBaseLockfile sets solely for the os.CreateTemp temp file it just created; a user-supplied --base-lockfile leaves autoDetectedBase false and is never removed, so the deleted path is always CLI-owned with no external control
		defer os.Remove(baseLockfile) //nolint:errcheck,gosec
	}

	// Without --all and without a usable base lockfile, only-new diffing is
	// impossible, so check silently audits every package — a different, stricter
	// mode than the default. detectBaseLockfile already announces the auto-detected
	// case (and an explicit --base-lockfile is the user's own choice), so surface
	// only the remaining silent path: no git base was found and the user did not
	// ask for --all. Say so plainly so the broader scope isn't mistaken for the
	// only-new default.
	if !scAll && baseLockfile == "" {
		s := output.GetStyles()
		fmt.Fprintf(os.Stderr, "%s %s\n",
			s.MutedText.Render("[armis]"),
			s.MutedText.Render("supply-chain: no git base detected, checking all packages (use --all to suppress this notice)"))
	}

	// Thread the approved registry for this lockfile's ecosystem (PPSC-994): age
	// checks query it, and npm-family packages resolved from a different host are
	// flagged. The URL was validated at config-load; validate once more defensively.
	registryURL := cfg.RegistryURLFor(eco)
	if registryURL != "" {
		if _, verr := supplychain.ValidateRegistryURL(registryURL); verr != nil {
			return fmt.Errorf("approved registry for %s is invalid: %w", eco, verr)
		}
	}

	ctx := cmd.Context()
	// armis:ignore cwe:73 cwe:22 reason:lockfilePath and baseLockfile derive from the user-controlled --lockfile/--base-lockfile CLI flags (or auto-detected paths) naming files on the user's own machine; reading them is the purpose of `supply-chain check`, same no-trust-boundary pattern as --output suppressed at the flag registration above
	result, err := check.RunCheckWithRegistry(ctx, policy, lockfilePath, baseLockfile, registryURL)
	if err != nil {
		if policy.FailOpen {
			cli.PrintWarningf("supply-chain check failed (--fail-open): %v", err)
			return nil
		}
		return err
	}

	for _, w := range result.Warnings {
		cli.PrintWarningf("%s", w)
	}

	if policy.FailOpen && len(result.Warnings) > 0 && len(result.Violations) == 0 {
		fmt.Fprintf(os.Stderr, "\n")
		cli.PrintWarningf("%d packages could not be checked (--fail-open: passing anyway)", len(result.Warnings))
	}

	s := output.GetStyles()

	// Coverage header LEADS the output when any registry is configured, so a
	// CISO reading CI logs sees exactly which ecosystems are covered and which
	// fall back to the public registry — never a green checkmark that implies
	// coverage the org isn't getting (E4/DX3 honesty).
	printRegistryCoverage(s, cfg, eco, registryURL, result.RegistryChecked)

	fmt.Fprintf(os.Stderr, "%s %s\n",
		s.MutedText.Render("[armis]"),
		s.MutedText.Render(fmt.Sprintf("supply-chain: checked %s, %d skipped, %s (%s policy)",
			countNoun(result.Checked, "package"), result.Skipped,
			countNoun(len(result.Violations), "violation"), policy.MinReleaseAge)))

	// WS3: write the compliance report when --report is set. The audit path has no
	// proxy-resolved fallbacks or one-hop conflicts, so those slices stay empty;
	// install_status reflects whether the audit found violations. Best-effort.
	if scReport != "" {
		blocked := make([]supplychain.BlockedPackage, 0, len(result.Violations))
		for _, v := range result.Violations {
			blocked = append(blocked, supplychain.BlockedPackage{
				Name:           v.Name,
				Version:        v.Version,
				DisplayVersion: v.Version,
				Age:            v.Age,
			})
		}
		status := statusOK
		if len(result.Violations) > 0 {
			status = statusFailed
		}
		rep := buildComplianceReport(reportInput{
			Policy:        policy,
			Mode:          "check",
			Ecosystem:     string(eco),
			Checked:       result.Checked,
			Blocked:       blocked,
			InstallStatus: status,
		})
		// armis:ignore cwe:22 cwe:23 cwe:73 reason:scReport is the user's own --report CLI flag naming an output file on their machine (identical trust model to scan's --output, suppressed at the same sink); a local CLI writing where its operator asked crosses no trust boundary, and the value is not attacker-controlled network input
		writeComplianceReport(scReport, rep)
	} // armis:ignore cwe:22 cwe:23 cwe:73 reason:scanner attributes the scReport write-path finding to this closing brace; scReport is the user's own --report CLI flag naming a file on their machine (same trust model as scan's --output), not attacker-controlled input crossing a trust boundary

	findings := make([]model.Finding, 0, len(result.Violations)+len(result.RegistryViolations))
	for _, v := range result.Violations {
		findings = append(findings, supplychain.ViolationToFinding(v, lockfilePath))
	}
	for _, rv := range result.RegistryViolations {
		findings = append(findings, registryViolationToFinding(rv, lockfilePath))
	}

	scanResult := &model.ScanResult{
		Status:   "completed",
		Findings: findings,
		Summary:  buildSummary(findings),
	}

	outputCfg, err := cmdutil.ResolveOutput(cmd, outputFile, format, colorFlag)
	if err != nil {
		return err
	}
	defer outputCfg.Cleanup()

	formatter, err := output.GetFormatter(outputCfg.Format)
	if err != nil {
		return err
	}

	opts := output.FormatOptions{
		RepoPath: dir,
	}
	if err := formatter.FormatWithOptions(scanResult, outputCfg.Writer, opts); err != nil {
		return fmt.Errorf("formatting output: %w", err)
	}

	// failOnSeverities was validated and uppercase-normalized at the top of this
	// function (before the scan ran) from the check-local scFailOn flag, so a
	// lowercase "medium" correctly trips ShouldFail's exact match here.
	return output.CheckExit(scanResult, failOnSeverities, exitCode)
}

// printRegistryCoverage emits the CISO-facing coverage header (E4/DX3). It
// prints NOTHING when no registry is configured anywhere (the pre-PPSC-994
// behavior — no header noise for users not using this feature). Once ANY
// registry is set, it states this ecosystem's coverage explicitly: a configured
// host with a scoped count, or "not configured — public registry" so a green
// check never implies coverage the org isn't getting.
func printRegistryCoverage(s *output.Styles, cfg *supplychain.Config, eco supplychain.Ecosystem, registryURL string, registryChecked int) {
	if !cfg.HasAnyRegistry() {
		return
	}

	ecoName := string(eco)
	if registryURL != "" {
		host := registryURL
		if u, err := url.Parse(registryURL); err == nil && u.Host != "" {
			host = u.Host
		}
		fmt.Fprintf(os.Stderr, "%s %s\n",
			s.MutedText.Render("[armis] Registry coverage:"),
			s.SuccessText.Render(fmt.Sprintf("%s ✓ (%s)", ecoName, host)))
		if isNPMFamilyEco(eco) {
			fmt.Fprintf(os.Stderr, "%s\n",
				s.MutedText.Render(fmt.Sprintf("  %s resolved-registry checked; packages from other registries are flagged.",
					countNoun(registryChecked, ecoName+" package"))))
		}
		return
	}

	// No registry configured for THIS ecosystem, but one is set for another —
	// be explicit that this ecosystem falls back to the public registry.
	fmt.Fprintf(os.Stderr, "%s %s\n",
		s.MutedText.Render("[armis] Registry coverage:"),
		s.WarningText.Render(fmt.Sprintf("%s ✗ (not configured — public registry)", ecoName)))
}

// isNPMFamilyEco reports whether an ecosystem is part of the npm family (the
// only family whose lockfiles record a per-package resolved registry URL, and
// thus the only one the non-approved-registry check covers in v1). Mirrors
// check.isNPMFamily without exporting it across the package boundary.
func isNPMFamilyEco(eco supplychain.Ecosystem) bool {
	switch eco {
	case supplychain.EcosystemNPM, supplychain.EcosystemPNPM, supplychain.EcosystemBun, supplychain.EcosystemYarn:
		return true
	default:
		return false
	}
}

// registryViolationToFinding converts a non-approved-registry violation into a
// model.Finding so it flows through the existing output formatters and the
// --fail-on gate, mirroring ViolationToFinding's shape. Severity is MEDIUM:
// resolving from an unapproved registry is a policy/routing concern, not the
// HIGH-severity "brand-new release" age signal.
func registryViolationToFinding(rv check.RegistryViolation, lockfilePath string) model.Finding {
	return model.Finding{
		ID:              fmt.Sprintf("SUPPLY_CHAIN_REGISTRY/%s@%s", rv.Name, rv.Version),
		Type:            model.FindingTypeSCA,
		Severity:        model.SeverityMedium,
		Title:           fmt.Sprintf("Package resolved from non-approved registry: %s@%s", rv.Name, rv.Version),
		Description:     fmt.Sprintf("Package %s@%s was resolved from %s, which is not the approved registry (%s). Re-resolve it through the approved registry.", rv.Name, rv.Version, rv.ResolvedHost, rv.ApprovedHost),
		File:            lockfilePath,
		Package:         rv.Name,
		Version:         rv.Version,
		FindingCategory: "SUPPLY_CHAIN_REGISTRY",
	}
}

// countNoun formats a count with its noun, pluralizing with a trailing "s" when
// the count is not exactly 1 (e.g. "1 package", "2 packages", "0 violations").
// Use countNounPlural for nouns whose plural is not formed by a trailing "s".
func countNoun(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// countNounPlural is countNoun for a noun whose plural is irregular — the
// trailing-"s" rule would mangle it (e.g. "dependency" → "dependencys"). It
// takes the explicit plural form rather than guessing, so "1 young transitive
// dependency" / "2 young transitive dependencies" both read correctly.
func countNounPlural(n int, singular, plural string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, singular)
	}
	return fmt.Sprintf("%d %s", n, plural)
}

func buildSummary(findings []model.Finding) model.Summary {
	summary := model.Summary{
		Total:      len(findings),
		BySeverity: make(map[model.Severity]int),
		ByType:     make(map[model.FindingType]int),
		ByCategory: make(map[string]int),
	}
	for _, f := range findings {
		summary.BySeverity[f.Severity]++
		summary.ByType[f.Type]++
		if f.FindingCategory != "" {
			summary.ByCategory[f.FindingCategory]++
		}
	}
	return summary
}

func detectBaseLockfile(ctx context.Context, lockfilePath string) string {
	if _, err := exec.LookPath("git"); err != nil {
		return ""
	}

	// Bound every git subprocess so a wedged invocation cannot hang the check.
	// Derived from the command context, so SIGINT still cancels earlier.
	ctx, cancel := context.WithTimeout(ctx, baseDetectGitTimeout)
	defer cancel()

	// Anchor every git invocation to the directory that contains the lockfile,
	// not the process's cwd. Otherwise `armis-cli supply-chain check
	// /other/repo` (or a --lockfile outside cwd) resolves base detection
	// against the wrong repository: rev-parse would report the cwd's repo and
	// `git show origin/main:<relPath>` could read an unrelated file.
	absLockfile, err := filepath.Abs(lockfilePath)
	if err != nil {
		return ""
	}
	gitWorkDir := filepath.Dir(absLockfile)

	gitDir := exec.CommandContext(ctx, "git", "rev-parse", "--git-dir") //nolint:gosec // detecting git repo
	gitDir.Dir = gitWorkDir
	if err := gitDir.Run(); err != nil {
		return ""
	}

	showTopLevel := exec.CommandContext(ctx, "git", "rev-parse", "--show-toplevel") //nolint:gosec
	showTopLevel.Dir = gitWorkDir
	topLevel, err := showTopLevel.Output()
	if err != nil {
		return ""
	}
	// TrimRight (not a fixed-length slice) drops the trailing newline: it is
	// panic-safe if git unexpectedly returns empty output and also tolerates a
	// "\r\n" line ending.
	root := filepath.Clean(strings.TrimRight(string(topLevel), "\r\n"))
	if root == "" || root == "." {
		return ""
	}

	relPath, err := filepath.Rel(root, absLockfile)
	if err != nil {
		return ""
	}
	// Reject any lockfile that resolves outside the repository tree. filepath.Rel
	// yields a ".."-prefixed (or absolute) path when absLockfile escapes root, so
	// this ensures the pathspec handed to "git show <rev>:<path>" stays within the
	// repo and cannot be steered at arbitrary files via traversal components.
	if relPath == ".." || strings.HasPrefix(relPath, ".."+string(filepath.Separator)) || filepath.IsAbs(relPath) {
		return ""
	}
	// Use forward slashes: git pathspecs are always '/'-separated, even on Windows.
	relPath = filepath.ToSlash(relPath)

	for _, base := range []string{"origin/main", "origin/master"} {
		// armis:ignore cwe:22 reason:relPath is confined to the repo tree by the traversal guard above and git resolves the pathspec within the repo; base is one of two hardcoded refs
		showBase := exec.CommandContext(ctx, "git", "show", base+":"+relPath) //nolint:gosec // user's git repo
		showBase.Dir = gitWorkDir
		content, err := showBase.Output()
		if err != nil {
			continue
		}

		tmpFile, err := os.CreateTemp("", "armis-supply-chain-base-*"+filepath.Ext(lockfilePath))
		if err != nil {
			return ""
		}
		if _, err := tmpFile.Write(content); err != nil {
			tmpFile.Close()           //nolint:errcheck,gosec
			os.Remove(tmpFile.Name()) //nolint:errcheck,gosec
			return ""
		}
		tmpFile.Close() //nolint:errcheck,gosec
		cli.PrintWarningf("auto-detected base lockfile from %s (use --all to check all packages)", base)
		return tmpFile.Name()
	}

	return ""
}

func resolvePolicy(cmd *cobra.Command, dir string) (supplychain.Policy, error) {
	cfg, _, err := loadConfigUpward(dir)
	if err != nil {
		return supplychain.Policy{}, err
	}

	var policy supplychain.Policy
	if cfg != nil {
		policy, err = cfg.ToPolicy()
		if err != nil {
			return supplychain.Policy{}, err
		}
	} else {
		policy = supplychain.DefaultPolicy()
	}

	if cmd.Flags().Changed("min-age") {
		d, err := supplychain.ParseDuration(scMinAge)
		if err != nil {
			return supplychain.Policy{}, fmt.Errorf("invalid --min-age: %w", err)
		}
		policy.MinReleaseAge = d
	}

	if cmd.Flags().Changed("exclude") {
		policy.Exclusions = scExclude
	}

	// The explicit --fail-open flag overrides the config value; otherwise
	// policy.FailOpen already carries the config setting (false by default).
	// Threading this through the policy avoids mutating the package-level
	// scFailOpen var as a hidden side effect that would persist across calls.
	if cmd.Flags().Changed("fail-open") {
		policy.FailOpen = scFailOpen
	}

	return policy, nil
}
