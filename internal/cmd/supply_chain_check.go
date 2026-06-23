package cmd

import (
	"context"
	"fmt"
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
	// --format, --fail-on, and --exit-code are persistent flags on scanCmd, but
	// supply-chain is a sibling of scan in the command tree and does not inherit
	// them. runSupplyChainCheck consumes all three (the format/failOn/exitCode
	// globals), so register them locally to match the scan commands. Defaults
	// mirror the former root registrations exactly.
	scCheckCmd.Flags().StringVarP(&format, "format", "f", getEnvOrDefault("ARMIS_FORMAT", "human"), "Output format: human, json, sarif, junit")
	scCheckCmd.Flags().StringSliceVar(&failOn, "fail-on", defaultFailOn(), "Exit with error on findings at these severity levels: INFO, LOW, MEDIUM, HIGH, CRITICAL")
	scCheckCmd.Flags().IntVar(&exitCode, "exit-code", 1, "Exit code when --fail-on triggers")
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
	// matches exactly) trips on a lowercase "medium".
	failOnSeverities, err := cmdutil.GetFailOn(failOn)
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
		return fmt.Errorf("lockfile not found: %s", lockfilePath)
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
		defer os.Remove(baseLockfile) //nolint:errcheck,gosec
	}

	ctx := cmd.Context()
	result, err := check.RunCheck(ctx, policy, lockfilePath, baseLockfile)
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
	}

	findings := make([]model.Finding, 0, len(result.Violations))
	for _, v := range result.Violations {
		findings = append(findings, supplychain.ViolationToFinding(v, lockfilePath))
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
	// function (before the scan ran), so a lowercase "medium" correctly trips
	// ShouldFail's exact match here.
	return output.CheckExit(scanResult, failOnSeverities, exitCode)
}

// countNoun formats a count with its noun, pluralizing with a trailing "s" when
// the count is not exactly 1 (e.g. "1 package", "2 packages", "0 violations").
func countNoun(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
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
