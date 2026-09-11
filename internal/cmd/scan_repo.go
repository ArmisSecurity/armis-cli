package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/api"
	"github.com/ArmisSecurity/armis-cli/internal/cmd/cmdutil"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/scan"
	"github.com/ArmisSecurity/armis-cli/internal/scan/repo"
	"github.com/spf13/cobra"
)

// changedRef holds the value for the --changed flag (repo-specific, not shared with scan image).
var changedRef string

// showSuppressed controls whether findings suppressed by .armisignore are displayed.
var showSuppressed bool

var scanRepoCmd = &cobra.Command{
	Use:   "repo [path] [file...]",
	Short: "Scan a local repository",
	Long:  `Scan a local repository for security vulnerabilities, secrets, and license risks.`,
	Example: `  $ armis-cli scan repo .
  $ armis-cli scan repo . --format json
  $ armis-cli scan repo . --format sarif --fail-on HIGH,CRITICAL
  $ armis-cli scan repo . --sbom --sbom-output sbom.json
  $ armis-cli scan repo . --sbom --sbom-format spdx
  $ armis-cli scan repo . --changed
  $ armis-cli scan repo . --changed=staged
  $ armis-cli scan repo . --changed=main
  $ armis-cli scan repo . src/app.py src/db.py`,
	// ArbitraryArgs, validated in RunE: the first argument is the optional repository
	// path (defaults to the current directory, matching every example and `scan
	// image`'s arg handling), and any argument after it is a file to scan. The
	// trailing form exists so a tool that appends selected filenames to a fixed
	// command line -- pre-commit with `pass_filenames: true`, xargs, a git hook --
	// can drive `scan repo` without knowing about --include-files.
	//
	// Because this accepts what MaximumNArgs(1) used to reject, RunE does the
	// rejecting instead, and does all of it before the first network call.
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		repoPath := "."
		if len(args) > 0 {
			repoPath = args[0]
		}

		var trailingFiles []string
		if len(args) > 1 {
			trailingFiles = args[1:]
		}

		// MarkFlagsMutuallyExclusive covers --include-files vs --changed; positional
		// files need the same guard for the same reason: --changed derives its own
		// file list, so a second, contradictory one would be silently discarded.
		if len(trailingFiles) > 0 && cmd.Flags().Changed("changed") {
			return fmt.Errorf("cannot use --changed together with positional file arguments")
		}

		// Trailing arguments are files, merged with --include-files rather than
		// conflicting with it: both name the same thing, a subset of the repository
		// to analyse. ParseFileList de-duplicates, so naming one file through both
		// does not spend the MaxFiles budget twice.
		selectedFiles := make([]string, 0, len(includeFiles)+len(trailingFiles))
		selectedFiles = append(selectedFiles, includeFiles...)
		selectedFiles = append(selectedFiles, trailingFiles...)

		// Validate path exists and is a directory before making network calls
		// armis:ignore cwe:22 reason:os.Stat is read-only existence check; path is from direct CLI arg, not untrusted input
		info, err := os.Stat(repoPath)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("path does not exist: %s", repoPath)
			}
			return fmt.Errorf("cannot access path %s: %w", repoPath, err)
		}
		if !info.IsDir() {
			// The hint is unconditional. A script forwarding a single changed
			// filename (`scan repo app.py`) makes exactly the same mistake as
			// `scan repo app.py db.py`, and at one argument the plain message is
			// least likely to explain it.
			return fmt.Errorf("path is not a directory: %s "+
				"(the first argument is the repository path; pass files after it, "+
				"e.g. `scan repo . %s`)", repoPath, repoPath)
		}

		// Resolve and validate the file selection here, before any network call.
		// Cobra's Args stage used to reject a malformed invocation for free;
		// ArbitraryArgs moved that work into RunE, so it has to stay ahead of
		// getAuthProvider -- a traversal path or an over-large list is a usage
		// error and must not cost a live token exchange.
		// Security: Path traversal protection is enforced by ParseFileList which
		// validates all paths using SafeJoinPath to ensure they don't escape the
		// repository root. Invalid or traversal paths are rejected with an error.
		var fileList *repo.FileList
		if len(selectedFiles) > 0 {
			absPath, err := filepath.Abs(repoPath) // armis:ignore cwe:770 reason:no bound needed here, this only resolves a path; scanner flags this line but the actual MaxFiles=1000 bound is enforced by ParseFileList below
			if err != nil {
				return fmt.Errorf("failed to resolve path: %w", err)
			}
			// armis:ignore cwe:22 cwe:770 reason:absPath is derived from filepath.Abs() immediately above; ParseFileList validates paths via SafeJoinPath and enforces MaxFiles=1000
			fileList, err = repo.ParseFileList(absPath, selectedFiles)
			if err != nil {
				source := fileSelectionSource(len(includeFiles), len(trailingFiles))
				// An over-large selection is an error, not a whole-repository
				// fallback: falling back would change what the exit code covers,
				// and it would silently turn the documented --include-files
				// overflow error into a passing full scan. One limit, one
				// behaviour -- the same one --changed has always had.
				if errors.Is(err, repo.ErrTooManyFiles) {
					return fmt.Errorf("%s: %w (scan the whole repository by selecting no files, "+
						"or select by git status with --changed)", source, err)
				}
				return fmt.Errorf("%s: %w", source, err)
			}
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

		warnOnUnusedSBOMVEXFlags()

		// Configure SBOM/VEX options if any flags are set
		if generateSBOM || generateVEX {
			sbomVEXOpts := &scan.SBOMVEXOptions{
				GenerateSBOM: generateSBOM,
				SBOMFormat:   sbomFormat,
				GenerateVEX:  generateVEX,
				SBOMOutput:   sbomOutput,
				VEXOutput:    vexOutput,
			}
			scanner = scanner.WithSBOMVEXOptions(sbomVEXOpts)
		}

		// Enable best-effort git-hint detection (repo_name / git_sha / origin_sha)
		// for incremental-scan baseline resolution — but only for a full-repo-root
		// upload. A --changed or --include-files partial upload is not a faithful
		// whole-repo snapshot, so a full-repo baseline diff against it would be
		// meaningless; skip detection entirely in those modes. DetectGitHints
		// additionally verifies the target is the repository root.
		if fileList == nil && !cmd.Flags().Changed("changed") {
			scanner = scanner.WithGitHints()
		}

		// Apply the targeted file selection validated above (--include-files
		// and/or trailing file arguments).
		if fileList != nil {
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
				// --changed reaches the same MaxFiles limit through the same
				// ParseFileList, so it gets the same remediation. Without this the
				// sibling path one function away names the alternatives and this one
				// returns a bare limit message. The alternatives differ: the way out of
				// an over-large --changed selection is a smaller range, not a smaller
				// file list.
				if errors.Is(err, repo.ErrTooManyFiles) {
					return fmt.Errorf("--changed: %w (scan the whole repository by dropping --changed, "+
						"or narrow the range, e.g. --changed=staged)", err)
				}
				return fmt.Errorf("--changed: %w", err)
			}

			scanner = scanner.WithIncludeFiles(fileList)
		}

		ctx, cancel := NewSignalContext()
		defer cancel()

		// armis:ignore cwe:22 reason:repoPath is from direct CLI argument; validated as existing directory above
		result, err := scanner.Scan(ctx, repoPath)
		if err != nil {
			return handleScanError(ctx, err)
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

		if err := formatter.FormatWithOptions(result, outputCfg.Writer, opts); err != nil {
			return fmt.Errorf("failed to format output: %w", err)
		}

		return output.CheckExit(result, failOnSeverities, exitCode)
	},
}

// fileSelectionSource names where a file selection came from, so a rejected path
// points at the flag or the argument the caller actually used. `scan repo .
// ../../etc/passwd` used to be reported as "invalid --include-files", naming a
// flag that was never passed.
func fileSelectionSource(fromFlag, fromArgs int) string {
	switch {
	case fromFlag > 0 && fromArgs > 0:
		return "invalid file selection"
	case fromArgs > 0:
		return "invalid file argument"
	default:
		return "invalid --include-files"
	}
}

func init() {
	scanRepoCmd.Flags().StringSliceVar(&includeFiles, "include-files", nil,
		"Comma-separated list of file paths to include in scan (relative to repository root)")
	scanRepoCmd.Flags().BoolVar(&showSuppressed, "show-suppressed", false,
		"Show findings suppressed by .armisignore directives")
	scanRepoCmd.Flags().StringVar(&changedRef, "changed", "",
		"Scan only git-changed files: --changed for uncommitted, "+
			"--changed=staged for staged only, --changed=REF for changes vs a branch/tag "+
			"(e.g., --changed=main). Note: 'staged' and 'uncommitted' are reserved and cannot be used as ref names")
	// NoOptDefVal is the value used when --changed is passed without a value
	scanRepoCmd.Flags().Lookup("changed").NoOptDefVal = "uncommitted"
	scanRepoCmd.MarkFlagsMutuallyExclusive("include-files", "changed")
	scanCmd.AddCommand(scanRepoCmd)
}
