package cmd

import (
	"fmt"
	"os"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/protect"
	"github.com/ArmisSecurity/armis-cli/internal/protect/check"
	"github.com/spf13/cobra"
)

var (
	protectMinAge       string
	protectExclude      []string
	protectBaseLockfile string
	protectLockfile     string
	protectAll          bool
	protectFailOpen     bool
)

var protectCheckCmd = &cobra.Command{
	Use:   "check [path]",
	Short: "Audit lockfile for recently-published packages",
	Long: `Check your lockfile for packages that were published too recently.

By default, checks only packages that are new compared to the base branch lockfile
(auto-detected in a git repository). Use --all to check all packages.

This command queries the public npm registry for publish dates. No Armis Cloud
authentication is required.`,
	Example: `  # Check current directory (auto-detects lockfile)
  armis-cli protect check

  # Check with custom policy
  armis-cli protect check --min-age 7d --exclude "@myorg/*"

  # Check all packages (not just new ones)
  armis-cli protect check --all

  # CI usage with SARIF output
  armis-cli protect check --format sarif --fail-on high

  # Fail gracefully if registry is unreachable
  armis-cli protect check --fail-open`,
	Args: cobra.MaximumNArgs(1),
	RunE: runProtectCheck,
}

func init() {
	protectCheckCmd.Flags().StringVar(&protectMinAge, "min-age", "72h", "Minimum release age threshold (e.g., 72h, 3d, 1w)")
	protectCheckCmd.Flags().StringSliceVar(&protectExclude, "exclude", nil, "Package patterns to exclude (glob syntax, e.g., @myorg/*)")
	protectCheckCmd.Flags().StringVar(&protectBaseLockfile, "base-lockfile", "", "Base lockfile to diff against (only report new packages)")
	protectCheckCmd.Flags().StringVar(&protectLockfile, "lockfile", "", "Explicit lockfile path (overrides auto-detection)")
	protectCheckCmd.Flags().BoolVar(&protectAll, "all", false, "Check all packages (disable auto-diff against base branch)")
	protectCheckCmd.Flags().BoolVar(&protectFailOpen, "fail-open", false, "Exit 0 on registry errors (fail-open for CI availability)")

	protectCmd.AddCommand(protectCheckCmd)
}

func runProtectCheck(cmd *cobra.Command, args []string) error {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}

	minAge, err := protect.ParseDuration(protectMinAge)
	if err != nil {
		return fmt.Errorf("invalid --min-age: %w", err)
	}

	policy := protect.Policy{
		MinReleaseAge: minAge,
		Exclusions:    protectExclude,
	}

	lockfilePath := protectLockfile
	if lockfilePath == "" {
		ecosystems, err := protect.DetectEcosystems(dir)
		if err != nil {
			return err
		}
		lockfilePath = ecosystems[0].LockfilePath
	}

	if _, err := os.Stat(lockfilePath); err != nil {
		return fmt.Errorf("lockfile not found: %s", lockfilePath)
	}

	baseLockfile := protectBaseLockfile

	ctx := cmd.Context()
	result, err := check.RunCheck(ctx, policy, lockfilePath, baseLockfile)
	if err != nil {
		if protectFailOpen {
			cli.PrintWarningf("protect check failed (--fail-open): %v", err)
			return nil
		}
		return err
	}

	for _, w := range result.Warnings {
		cli.PrintWarningf("%s", w)
	}

	if protectFailOpen && len(result.Warnings) > 0 && len(result.Violations) == 0 {
		fmt.Fprintf(os.Stderr, "\n")
		cli.PrintWarningf("%d packages could not be checked (--fail-open: passing anyway)", len(result.Warnings))
	}

	findings := make([]model.Finding, 0, len(result.Violations))
	for _, v := range result.Violations {
		findings = append(findings, protect.ViolationToFinding(v, lockfilePath))
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
