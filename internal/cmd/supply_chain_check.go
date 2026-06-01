package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/supplychain"
	"github.com/ArmisSecurity/armis-cli/internal/supplychain/check"
	"github.com/spf13/cobra"
)

var (
	scMinAge       string
	scExclude      []string
	scBaseLockfile string
	scLockfile     string
	scAll          bool
	scFailOpen     bool
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

	supplyChainCmd.AddCommand(scCheckCmd)
}

func runSupplyChainCheck(cmd *cobra.Command, args []string) error {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
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

	if _, err := os.Stat(lockfilePath); err != nil {
		return fmt.Errorf("lockfile not found: %s", lockfilePath)
	}

	var baseLockfile string
	var autoDetectedBase bool
	if !scAll {
		if scBaseLockfile != "" {
			baseLockfile = scBaseLockfile
		} else {
			baseLockfile = detectBaseLockfile(lockfilePath)
			autoDetectedBase = baseLockfile != ""
		}
	}
	if autoDetectedBase {
		defer os.Remove(baseLockfile) //nolint:errcheck,gosec
	}

	ctx := cmd.Context()
	result, err := check.RunCheck(ctx, policy, lockfilePath, baseLockfile)
	if err != nil {
		if scFailOpen {
			cli.PrintWarningf("supply-chain check failed (--fail-open): %v", err)
			return nil
		}
		return err
	}

	for _, w := range result.Warnings {
		cli.PrintWarningf("%s", w)
	}

	if scFailOpen && len(result.Warnings) > 0 && len(result.Violations) == 0 {
		fmt.Fprintf(os.Stderr, "\n")
		cli.PrintWarningf("%d packages could not be checked (--fail-open: passing anyway)", len(result.Warnings))
	}

	s := output.GetStyles()
	fmt.Fprintf(os.Stderr, "%s %s\n",
		s.MutedText.Render("[armis]"),
		s.MutedText.Render(fmt.Sprintf("supply-chain: checked %d packages, %d skipped, %d violations (%s policy)",
			result.Checked, result.Skipped, len(result.Violations), policy.MinReleaseAge)))

	findings := make([]model.Finding, 0, len(result.Violations))
	for _, v := range result.Violations {
		findings = append(findings, supplychain.ViolationToFinding(v, lockfilePath))
	}

	scanResult := &model.ScanResult{
		Status:   "completed",
		Findings: findings,
		Summary:  buildSummary(findings),
	}

	outputCfg, err := ResolveOutput(cmd, outputFile, format, colorFlag)
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

	return output.CheckExit(scanResult, failOn, exitCode)
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

func detectBaseLockfile(lockfilePath string) string {
	if _, err := exec.LookPath("git"); err != nil {
		return ""
	}

	gitDir := exec.Command("git", "rev-parse", "--git-dir") //nolint:gosec // detecting git repo
	if err := gitDir.Run(); err != nil {
		return ""
	}

	topLevel, err := exec.Command("git", "rev-parse", "--show-toplevel").Output() //nolint:gosec
	if err != nil {
		return ""
	}
	root := filepath.Clean(string(topLevel[:len(topLevel)-1]))

	absLockfile, err := filepath.Abs(lockfilePath)
	if err != nil {
		return ""
	}
	relPath, err := filepath.Rel(root, absLockfile)
	if err != nil {
		return ""
	}

	for _, base := range []string{"origin/main", "origin/master"} {
		content, err := exec.Command("git", "show", base+":"+relPath).Output() //nolint:gosec // user's git repo
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
		if cfg.FailOpen && !cmd.Flags().Changed("fail-open") {
			scFailOpen = true
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

	return policy, nil
}
