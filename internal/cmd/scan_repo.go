package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/api"
	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/cmd/cmdutil"
	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/project"
	"github.com/ArmisSecurity/armis-cli/internal/scan"
	"github.com/ArmisSecurity/armis-cli/internal/scan/repo"
	"github.com/spf13/cobra"
)

// changedRef holds the value for the --changed flag (repo-specific, not shared with scan image).
var changedRef string

// showSuppressed controls whether findings suppressed by .armisignore are displayed.
var showSuppressed bool

// includeSBOMFiles holds the value for the --include-sbom-files flag: the
// maximum number of SBOM files to scan alongside the code (0 = flag not set).
var includeSBOMFiles int

// maxIncludeSBOMFiles is the largest --include-sbom-files value, the most SBOM
// files the server scans for any tenant.
const maxIncludeSBOMFiles = 1000

// Project publishing flags, shared by `scan repo` and the
// `scan <path>` shorthand.
var (
	// projectName is --project: the AppSec project a published scan is
	// recorded on. Empty means the scan is local-only.
	projectName string
	// reportScan is --report: publish a scan run outside CI.
	reportScan bool
	// syncScan is --sync: wait for results and gate (the default behavior).
	syncScan bool
	// asyncScan is --async: return once the scan is accepted.
	asyncScan bool
)

var scanRepoCmd = &cobra.Command{
	Use:   "repo [path]",
	Short: "Scan a local repository",
	Long: `Scan a local repository for security vulnerabilities, secrets, and license risks.

The path does not have to be a git repository: any folder (a non-git codebase,
or a subfolder of a monorepo) can be scanned. 'armis-cli scan <path>' is a
shorthand for this command.

By default a scan is local-only: findings are printed and --fail-on sets the
exit code, like a linter, and nothing is published. With --project <name> a CI
run is published as a run of that AppSec project, which is created on first
use; a run on a developer machine is published only with --report.`,
	Example: `  $ armis-cli scan repo .
  $ armis-cli scan repo . --format json
  $ armis-cli scan repo . --format sarif --fail-on HIGH,CRITICAL
  $ armis-cli scan repo . --sbom --sbom-output sbom.json
  $ armis-cli scan repo . --sbom --sbom-format spdx
  $ armis-cli scan repo . --bom aibom,cbom
  $ armis-cli scan repo . --bom all --bom-format cyclonedx-1.6 --bom-output ./boms
  $ armis-cli scan repo . --changed
  $ armis-cli scan repo . --changed=staged
  $ armis-cli scan repo . --changed=main
  $ armis-cli scan repo . --include-sbom-files 20

  # Publish to a project (in CI; add --report on a developer machine)
  $ armis-cli scan repo . --project checkout-service
  $ armis-cli scan repo . --project checkout-service --async`,
	// MaximumNArgs(1) (not ExactArgs(1)) makes the `[path]` in Use honest: the path
	// is optional and defaults to the current directory, matching every example and
	// `scan image`'s arg handling.
	Args: cobra.MaximumNArgs(1),
	RunE: runRepoScan,
}

// addRepoScanFlags registers the flags of a repository scan on cmd. `scan repo`
// and the `scan <path>` shorthand both run runRepoScan, so they take the same
// flags, bound to the same variables.
func addRepoScanFlags(cmd *cobra.Command) {
	cmd.Flags().StringSliceVar(&includeFiles, "include-files", nil, includeFilesUsage)
	cmd.Flags().BoolVar(&showSuppressed, "show-suppressed", false,
		"Show findings suppressed by .armisignore directives")
	cmd.Flags().StringVar(&changedRef, "changed", "",
		"Scan only git-changed files: --changed for uncommitted, "+
			"--changed=staged for staged only, --changed=REF for changes vs a branch/tag "+
			"(e.g., --changed=main). Note: 'staged' and 'uncommitted' are reserved and cannot be used as ref names")
	// NoOptDefVal is the value used when --changed is passed without a value
	cmd.Flags().Lookup("changed").NoOptDefVal = "uncommitted"
	cmd.MarkFlagsMutuallyExclusive("include-files", "changed")
	// The limit is required (no NoOptDefVal) so "--include-sbom-files 20" parses
	// as a limit of 20 rather than as a path argument.
	cmd.Flags().IntVar(&includeSBOMFiles, "include-sbom-files", 0,
		"Also scan the repository's SBOM files (CycloneDX, SPDX) for vulnerabilities, "+
			"at most N of them, 1 to 1000 (e.g., --include-sbom-files 20). The server may apply a lower limit")

	cmd.Flags().StringVar(&projectName, "project", "",
		"AppSec project to publish the scan to, created on first use (1-64 letters, digits, '.', '_', '-', '/'). "+
			"Publishes automatically in CI, and with --report elsewhere; without it the scan is local-only")
	cmd.Flags().BoolVar(&reportScan, "report", false,
		"Publish a scan run outside CI to its --project (CI runs publish without it)")
	cmd.Flags().BoolVar(&syncScan, "sync", false,
		"Wait for the results and exit non-zero when --fail-on triggers (the default)")
	cmd.Flags().BoolVar(&asyncScan, "async", false,
		"Return as soon as the scan is accepted, without waiting for results: exits 0 once accepted "+
			"and does not evaluate --fail-on (follow up with 'armis-cli scan status')")
	cmd.MarkFlagsMutuallyExclusive("sync", "async")
}

// scanTargetError is a scan target that could not be looked up. Its message is
// what the repository scan has always printed; the type lets the `scan <path>`
// shorthand add a hint about subcommands and image references.
type scanTargetError struct {
	Path string
	Err  error
}

func (e *scanTargetError) Error() string {
	if os.IsNotExist(e.Err) {
		return "path does not exist: " + e.Path
	}
	return fmt.Sprintf("cannot access path %s: %v", e.Path, e.Err)
}

func (e *scanTargetError) Unwrap() error { return e.Err }

// runRepoScan is the RunE of `scan repo` and of the `scan <path>` shorthand.
func runRepoScan(cmd *cobra.Command, args []string) error {
	repoPath := repoArg(args)
	if err := validateIncludeSBOMFiles(cmd); err != nil {
		return err
	}

	// Check the publishing flags first, so an invalid --project fails before
	// anything is read, authenticated or uploaded.
	decision, err := validatePublishFlags(cmd)
	if err != nil {
		return err
	}

	// The BOM type and format pairs, --bom-output, and a default .armis
	// that is not a plain directory fail before any network call;
	// PersistentPreRunE has normalized the values.
	if err = cmdutil.ValidateBOMFlags(cmdutil.ScanBOMFlags, bomTypes, bomFormat, bomOutput); err != nil {
		return err
	}
	if err = checkDefaultOutputDir(); err != nil {
		return err
	}

	// Validate path exists and is a directory before making network calls
	// armis:ignore cwe:22 reason:os.Stat is read-only existence check; path is from direct CLI arg, not untrusted input
	info, err := os.Stat(repoPath)
	if err != nil {
		return &scanTargetError{Path: repoPath, Err: err}
	}
	if !info.IsDir() {
		return fmt.Errorf("path is not a directory: %s", repoPath)
	}

	authProvider, err := getAuthProvider(cmd.Context())
	if err != nil {
		return err
	}
	// Defensive nil-check. getAuthProvider returns (nil, err) on
	// failure and (non-nil, nil) on success — the explicit guard
	// here exists so a future refactor can't silently slip a nil
	// past the err check and crash the API client constructor.
	if authProvider == nil {
		return fmt.Errorf("internal error: nil auth provider")
	}

	tid, err := authProvider.GetTenantID(cmd.Context())
	if err != nil {
		return err
	}

	limit, err := getPageLimit()
	if err != nil {
		return err
	}

	failOnSeverities, err := cmdutil.GetFailOn(failOn)
	if err != nil {
		return err
	}

	baseURL := resolveDataPlaneURL(cmd.Context(), authProvider)
	client, err := api.NewClient(baseURL, authProvider, debug, time.Duration(uploadTimeout)*time.Minute,
		clientOptionsForBaseURL(baseURL)...)
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}
	scanTimeoutDuration := time.Duration(scanTimeout) * time.Minute
	scanner := repo.NewScanner(client, noProgress, tid, limit, includeTests, scanTimeoutDuration, includeNonExploitable)
	if pollInterval > 0 {
		scanner = scanner.WithPollInterval(pollInterval)
	}
	if includeSBOMFiles > 0 {
		scanner = scanner.WithSBOMFiles(includeSBOMFiles)
	}

	warnOnUnusedSBOMVEXFlags()
	warnOnUnusedBOMFlags()
	if asyncScan {
		warnOnAsyncIgnoredFlags(cmd)
	}

	// Configure SBOM/VEX/BOM options if any flags are set
	if generateSBOM || generateVEX || len(bomTypes) > 0 {
		sbomVEXOpts := &scan.SBOMVEXOptions{
			GenerateSBOM: generateSBOM,
			SBOMFormat:   sbomFormat,
			GenerateVEX:  generateVEX,
			SBOMOutput:   sbomOutput,
			VEXOutput:    vexOutput,
			BOM:          bomOptions(repoPath),
		}
		scanner = scanner.WithSBOMVEXOptions(sbomVEXOpts)
	}

	if wantGitHints(cmd) {
		scanner = scanner.WithGitHints()
	}

	// Handle --include-files flag for targeted file scanning
	if len(includeFiles) > 0 {
		fileList, err := parseIncludeFiles(repoPath)
		if err != nil {
			return err
		}
		scanner = scanner.WithIncludeFiles(fileList)
	}

	// Handle --changed flag for scanning only git-changed files
	if cmd.Flags().Changed("changed") {
		absPath, err := filepath.Abs(repoPath)
		if err != nil {
			return fmt.Errorf("failed to resolve path: %w", err)
		}

		var opts repo.ChangedOptions
		switch changedRef {
		case "uncommitted": // --changed (no value)
			opts = repo.ChangedOptions{Mode: repo.ChangedModeUncommitted}
		case "staged": // --changed=staged
			opts = repo.ChangedOptions{Mode: repo.ChangedModeStaged}
		case "": // --changed= (explicit empty value)
			return fmt.Errorf("--changed requires a value (e.g., --changed=main, --changed=staged), " +
				"or use --changed without '=' for uncommitted changes")
		default: // --changed=<ref>
			opts = repo.ChangedOptions{Mode: repo.ChangedModeRef, Ref: changedRef}
		}

		fileList, err := repo.GitChangedFiles(absPath, opts)
		if err != nil {
			if errors.Is(err, repo.ErrNotGitRepo) {
				return fmt.Errorf("--changed requires a git repository: %w", err)
			}
			if errors.Is(err, repo.ErrNoChangedFiles) {
				fmt.Fprintln(os.Stderr, "No changed files found - nothing to scan.")
				return nil
			}
			if errors.Is(err, repo.ErrRefNotFound) {
				return fmt.Errorf("--changed: git ref %q not found", changedRef)
			}
			if errors.Is(err, repo.ErrGitNotFound) {
				return fmt.Errorf("--changed: %w", err)
			}
			return fmt.Errorf("--changed: %w", err)
		}

		scanner = scanner.WithIncludeFiles(fileList)
	}

	// A --changed or --include-files upload holds only some files, and the
	// BOMs are built from the upload.
	if len(bomTypes) > 0 && (len(includeFiles) > 0 || cmd.Flags().Changed("changed")) {
		cli.PrintWarning("BOMs cover only the uploaded files")
	}

	ctx, cancel := NewSignalContext()
	defer cancel()

	// The scanner resolves (or creates) the project once its local checks
	// pass (path, .armisignore, size) and before it uploads: a scan rejected
	// locally never creates a project, and a credential or naming problem
	// still fails before the upload. If the upload or /ingest/scan itself
	// fails, the project exists with no runs and the next run reuses it.
	var published *project.Resolution
	var publishedRun *model.ProjectRun
	var resolveErr error
	if decision.Publish {
		scanner = scanner.WithProjectResolver(func(ctx context.Context, _ repo.IgnoreSummary) (string, string, bool, error) {
			published, resolveErr = project.Resolve(ctx, client, tid, projectName, project.ResolveOptions{})
			if resolveErr != nil {
				return "", "", false, resolveErr
			}
			announceProject(published, decision)
			return published.Project.ProjectID, decision.Trigger, false, nil
		}).WithProjectRunReporter(func(run *model.ProjectRun) {
			publishedRun = run
			reportProjectRun(published, run)
		})
	} else if projectName != "" {
		cli.PrintWarning(fmt.Sprintf("--project %s: this scan runs locally and is not published, "+
			"since no CI environment was detected. Add --report to publish it to the project "+
			"(CI runs publish automatically).", projectName))
	}

	if asyncScan {
		scanner = scanner.WithAsync()
	}

	// armis:ignore cwe:22 reason:repoPath is from direct CLI argument; validated as existing directory above
	result, err := scanner.Scan(ctx, repoPath)
	if err != nil {
		// A project lookup or create failure keeps its own message, not
		// handleScanError's "scan failed:" prefix.
		if resolveErr != nil {
			return resolveErr
		}
		return handleScanError(ctx, err)
	}

	if asyncScan {
		return renderAsyncAccepted(cmd, result, published, decision, publishedRun)
	}

	// Resolve output destination and format (handles file creation, format auto-detection, colors)
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
		GroupBy:          groupBy,
		RepoPath:         repoPath,
		Debug:            debug,
		SummaryTop:       summaryTop,
		FailOnSeverities: failOnSeverities,
		ShowSuppressed:   showSuppressed,
	}

	return bomExit(result, formatScanResult(formatter, result, reportWriter(outputCfg.Writer), opts, minSeverity, failOnSeverities))
}

// repoArg returns the repository path of scan repo and bom repo: the
// argument, or the current directory.
func repoArg(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	return "."
}

// wantGitHints reports whether a repo upload sends git hints. It enables
// best-effort git-hint detection (repo_name / git_sha / origin_sha) for
// incremental-scan baseline resolution, and for the name and version at the
// root of the BOMs, but only for a full-repo-root upload. A --changed or
// --include-files partial upload is not a faithful whole-repo snapshot, so a
// full-repo baseline diff against it would be meaningless; skip detection
// entirely in those modes. DetectGitHints additionally verifies the target
// is the repository root. bom repo has no --changed, which then reads as
// not given.
func wantGitHints(cmd *cobra.Command) bool {
	return len(includeFiles) == 0 && !cmd.Flags().Changed("changed")
}

// checkRepoPath checks that repoPath is an existing directory, before any
// network call.
func checkRepoPath(repoPath string) error {
	// armis:ignore cwe:22 reason:os.Stat is read-only existence check; path is from direct CLI arg, not untrusted input
	info, err := os.Stat(repoPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("path does not exist: %s", repoPath)
		}
		return fmt.Errorf("cannot access path %s: %w", repoPath, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("path is not a directory: %s", repoPath)
	}
	return nil
}

// parseIncludeFiles returns the --include-files list for the repository at
// repoPath.
// Security: Path traversal protection is enforced by ParseFileList which
// validates all paths using SafeJoinPath to ensure they don't escape the
// repository root. Invalid or traversal paths are rejected with an error.
func parseIncludeFiles(repoPath string) (*repo.FileList, error) {
	absPath, err := filepath.Abs(repoPath) // armis:ignore cwe:770 reason:no bound needed here, this only resolves a path; scanner flags this line but the actual MaxFiles=1000 bound is enforced by ParseFileList below
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path: %w", err)
	}
	// armis:ignore cwe:22 cwe:770 reason:absPath is derived from filepath.Abs() immediately above; ParseFileList validates paths via SafeJoinPath and enforces MaxFiles=1000
	fileList, err := repo.ParseFileList(absPath, includeFiles)
	if err != nil {
		return nil, fmt.Errorf("invalid --include-files: %w", err)
	}
	return fileList, nil
}

func init() {
	addRepoScanFlags(scanRepoCmd)
	scanCmd.AddCommand(scanRepoCmd)
}

// validateIncludeSBOMFiles rejects a --include-sbom-files limit outside 1 to
// maxIncludeSBOMFiles before any network call.
func validateIncludeSBOMFiles(cmd *cobra.Command) error {
	if !cmd.Flags().Changed("include-sbom-files") {
		return nil
	}
	if includeSBOMFiles < 1 || includeSBOMFiles > maxIncludeSBOMFiles {
		return fmt.Errorf("invalid --include-sbom-files value %d: must be between 1 and %d",
			includeSBOMFiles, maxIncludeSBOMFiles)
	}
	return nil
}
