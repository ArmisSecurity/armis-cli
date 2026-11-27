package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/cmd/cmdutil"
	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/scan"
	"github.com/ArmisSecurity/armis-cli/internal/scan/image"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	includeTests          bool
	scanTimeout           int
	uploadTimeout         int
	includeNonExploitable bool
	groupBy               string
	includeFiles          []string
	generateSBOM          bool
	sbomFormat            string
	generateVEX           bool
	sbomOutput            string
	vexOutput             string
	bomTypes              []string
	bomFormat             string
	bomOutput             string
	summaryTop            bool
	outputFile            string
	pollInterval          time.Duration
)

// Shared constants for the --format value across scan subcommands. `scan
// status` reuses these to keep goconst happy across cmd/ and to make the
// human/json spelling change in exactly one place if it ever needs to.
const (
	statusFormatHuman = "human"
	statusFormatJSON  = "json"
)

// validFormats contains the valid output format strings.
var validFormats = []string{statusFormatHuman, statusFormatJSON, "sarif", "junit"}

// validGroupBy contains the valid group-by options.
var validGroupBy = []string{"none", "cwe", "severity", "file"}

// validSBOMFormats contains the valid --sbom-format values. These mirror the
// backend SbomFormat enum and are sent verbatim in the ingest request.
var validSBOMFormats = []string{scan.SBOMFormatCycloneDX, scan.SBOMFormatSPDX}

// defaultFailOn returns the default --fail-on severity set. It returns a fresh
// slice on each call so the two flag registrations (scanCmd and scCheckCmd)
// never share backing storage — pflag parsing mutates a StringSlice's default
// in place, which would otherwise leak between the two flag instances.
func defaultFailOn() []string { return []string{"CRITICAL"} }

// failOnUsage describes --fail-on, which scan and supply-chain check share:
// a threshold, which a list sets at its lowest level (cmdutil.GetFailOn).
const failOnUsage = "Exit with error on findings at or above this severity: INFO, LOW, MEDIUM, HIGH, CRITICAL " +
	"(HIGH fails on HIGH and CRITICAL; a list counts from its lowest level; \"\" never fails)"

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan artifacts for security vulnerabilities",
	Long: `Scan repositories and container images for security vulnerabilities, secrets, and license risks.

'armis-cli scan <path>' scans a folder: it is a shorthand for 'armis-cli scan repo <path>'
and takes the same flags. Without --project the scan is local-only (findings and a
--fail-on exit code, nothing published); with --project a CI run is published to
that project, and a developer-machine run is published only with --report.`,
	Example: `  # Scan the current folder (shorthand for 'scan repo .')
  armis-cli scan .

  # Publish a CI scan to a project, created on first use
  armis-cli scan . --project checkout-service

  # Scan a repository
  armis-cli scan repo /path/to/repo

  # Scan a container image
  armis-cli scan image myapp:latest

  # Scan with SBOM generation
  armis-cli scan repo . --sbom --sbom-output sbom.json

  # Download an AI-BOM and a CBOM (BOM generation must be enabled for your tenant)
  armis-cli scan repo . --bom aibom,cbom

  # Check the status of the last scan (or a specific 24-character scan_id)
  armis-cli scan status
  armis-cli scan status 507f1f77bcf86cd799439011`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Call root command's PersistentPreRunE to initialize colors and update checking
		// We reference rootCmd directly since cmd.Parent() would return scanCmd for subcommands
		if rootCmd != nil && rootCmd.PersistentPreRunE != nil {
			if err := rootCmd.PersistentPreRunE(cmd, args); err != nil {
				return err
			}
		}

		// Validate format early to fail fast
		if _, err := output.GetFormatter(format); err != nil {
			return fmt.Errorf("invalid --format value %q: must be one of %v", format, validFormats)
		}

		// Validate group-by early
		validGroupBySet := make(map[string]bool)
		for _, g := range validGroupBy {
			validGroupBySet[g] = true
		}
		if !validGroupBySet[strings.ToLower(groupBy)] {
			return fmt.Errorf("invalid --group-by value %q: must be one of %v", groupBy, validGroupBy)
		}

		// Validate --sbom-format early (and normalize case) so a typo surfaces
		// as a flag error before any network calls.
		sbomFormat = strings.ToLower(sbomFormat)
		validSBOMFormatSet := make(map[string]bool)
		for _, f := range validSBOMFormats {
			validSBOMFormatSet[f] = true
		}
		if !validSBOMFormatSet[sbomFormat] {
			return fmt.Errorf("invalid --sbom-format value %q: must be one of %v", sbomFormat, validSBOMFormats)
		}

		// Validate the --bom and --bom-format values early, normalizing them in
		// place, so a bad value surfaces before auth and upload. The type and
		// format pairs and --bom-output are checked by scan repo and scan
		// image only: scan status and scan sbom ignore the BOM flags.
		bomFlag := cmd.Flag("bom")
		normalizedBOMTypes, normalizedBOMFormat, err := cmdutil.NormalizeBOMFlags(cmdutil.ScanBOMFlags, bomTypes, bomFlag != nil && bomFlag.Changed, bomFormat)
		if err != nil {
			return err
		}
		bomTypes, bomFormat = normalizedBOMTypes, normalizedBOMFormat

		// Validate exit-code: must be between 1 and 255 (0 defeats --fail-on, >255 is invalid POSIX)
		if exitCode < 1 || exitCode > 255 {
			return fmt.Errorf("invalid --exit-code value %d: must be between 1 and 255", exitCode)
		}

		if err := validateTimeouts(); err != nil {
			return err
		}

		// Validate --fail-on early so a typo (e.g. HIGHT) surfaces as a flag error
		// instead of silently defaulting once auth succeeds. ValidateFailOn also
		// normalizes the slice to uppercase in place, so the GetFailOn calls in the
		// subcommands' RunE become idempotent re-validation.
		if err := cmdutil.ValidateFailOn(failOn); err != nil {
			return err
		}

		// Validate --min-severity early for the same reason, normalizing it in
		// place so the subcommands' RunE can use the package global directly.
		normalizedMinSeverity, err := cmdutil.ValidateMinSeverity(minSeverity)
		if err != nil {
			return err
		}
		minSeverity = normalizedMinSeverity

		return nil
	},
}

// Defaults of --scan-timeout and --upload-timeout, in minutes.
const (
	defaultScanTimeout   = 60
	defaultUploadTimeout = 10
)

// Usage of --include-tests and --include-files, which scan and bom share.
const (
	includeTestsUsage = "Include test files in the scan (test files are excluded by default)"
	includeFilesUsage = "Comma-separated list of file paths to include in scan (relative to repository root)"
)

// validateTimeouts checks --scan-timeout and --upload-timeout: they must be
// positive and bounded.
func validateTimeouts() error {
	if scanTimeout < 1 {
		return fmt.Errorf("invalid --scan-timeout value %d: must be at least 1 minute", scanTimeout)
	}
	const maxScanTimeout = 1440 // 24 hours
	if scanTimeout > maxScanTimeout {
		return fmt.Errorf("invalid --scan-timeout value %d: must not exceed %d minutes (24 hours)", scanTimeout, maxScanTimeout)
	}
	if uploadTimeout < 1 {
		return fmt.Errorf("invalid --upload-timeout value %d: must be at least 1 minute", uploadTimeout)
	}
	const maxUploadTimeout = 120 // 2 hours
	if uploadTimeout > maxUploadTimeout {
		return fmt.Errorf("invalid --upload-timeout value %d: must not exceed %d minutes", uploadTimeout, maxUploadTimeout)
	}
	return nil
}

// addUploadFlags registers the persistent flags of a command whose
// subcommands upload an artifact and wait for the server: --no-progress,
// --scan-timeout, --upload-timeout and the hidden --poll-interval. scan and
// bom both call it, binding the same variables with the same defaults, so the
// order of their init functions does not matter.
func addUploadFlags(cmd *cobra.Command) {
	fs := cmd.PersistentFlags()
	fs.BoolVar(&noProgress, "no-progress", false, "Suppress progress output (for CI/scripts)")
	fs.IntVar(&scanTimeout, "scan-timeout", defaultScanTimeout, "Maximum time in minutes to wait for scan analysis to complete")
	fs.IntVar(&uploadTimeout, "upload-timeout", defaultUploadTimeout, "Maximum time in minutes to wait for artifact upload to complete")
	// poll-interval overrides the Scanner's default status-poll interval (5s in
	// repo/image/sbom Scanners). Hidden: it exists solely so RunE-level tests can
	// avoid burning a real poll tick, the same way package-level tests already do
	// via each Scanner's WithPollInterval builder, without going through cobra
	// flag parsing (RunE tests call scanXCmd.RunE directly, not cmd.Execute()).
	fs.DurationVar(&pollInterval, "poll-interval", 0, "Override the scan status poll interval (0 = use default)")
	_ = fs.MarkHidden("poll-interval")
}

// bomTypeCompletions and bomFormatCompletions return the completion functions
// for the BOM type and format flags: --bom and --bom-format on scan, --type
// and --format on bom.
func bomTypeCompletions() cobra.CompletionFunc {
	return fixedCompletions(scan.BOMTypeOrder, map[string]string{
		scan.BOMTypeSBOM:  "Software BOM",
		scan.BOMTypeAIBOM: "AI BOM: models, AI services and MCP servers",
		scan.BOMTypeCBOM:  "Cryptographic BOM",
		scan.BOMTypeAll:   "Combined BOM of all types",
	})
}

func bomFormatCompletions() cobra.CompletionFunc {
	return fixedCompletions(scan.BOMFormats, map[string]string{
		scan.BOMFormatCycloneDX17: "CycloneDX 1.7 JSON (default)",
		scan.BOMFormatCycloneDX16: "CycloneDX 1.6 JSON",
		scan.BOMFormatSPDX23:      "SPDX 2.3 JSON, sbom only",
		scan.BOMFormatSPDX301:     "SPDX 3.0.1 JSON, sbom and aibom",
		scan.BOMFormatCycloneDX:   "Alias of cyclonedx-1.7",
		scan.BOMFormatSPDX:        "Alias: spdx-2.3 for sbom, spdx-3.0.1 for aibom",
	})
}

// warnOnUnusedSBOMVEXFlags emits a warning when --sbom-output / --vex-output
// are set without their corresponding generation flag. Called by the
// subcommands that treat the flags as "output for a generated artifact"
// (scan repo, scan image). `scan sbom` repurposes both flags and skips it.
func warnOnUnusedSBOMVEXFlags() {
	if sbomOutput != "" && !generateSBOM {
		cli.PrintWarning("--sbom-output is ignored without --sbom flag")
	}
	// --sbom-format only takes effect when an SBOM is generated. sbomFormat is
	// normalized to lowercase in PersistentPreRunE, so compare against the
	// canonical default.
	if sbomFormat != scan.SBOMFormatCycloneDX && !generateSBOM {
		cli.PrintWarning("--sbom-format is ignored without --sbom flag")
	}
	if vexOutput != "" && !generateVEX {
		cli.PrintWarning("--vex-output is ignored without --vex flag")
	}
}

// warnOnUnusedBOMFlags emits a warning when --bom-format / --bom-output are
// set without --bom. bomTypes and bomFormat are normalized in
// PersistentPreRunE, so an empty bomTypes means no --bom, and the format is
// compared against the lower-case default.
func warnOnUnusedBOMFlags() {
	if len(bomTypes) > 0 {
		return
	}
	if bomFormat != scan.BOMFormatCycloneDX17 {
		cli.PrintWarning("--bom-format is ignored without --bom flag")
	}
	if bomOutput != "" {
		cli.PrintWarning("--bom-output is ignored without --bom flag")
	}
}

// checkDefaultOutputDir stops scan repo and scan image before auth and upload
// when --sbom, --vex or --bom would write to a default .armis that is not a
// plain directory, with the error the write would give after the scan. The
// write checks again.
func checkDefaultOutputDir() error {
	var docType string
	switch {
	case generateSBOM && sbomOutput == "":
		docType = "SBOM"
	case generateVEX && vexOutput == "":
		docType = "VEX"
	case len(bomTypes) > 0 && bomOutput == "":
		docType = scan.BOMLabel(bomTypes[0])
	default:
		return nil
	}
	return scan.CheckDefaultOutputDir(docType)
}

// bomOptions returns the BOM download options for a scan of target (as
// typed), or nil without --bom.
func bomOptions(target string) *scan.BOMOptions {
	if len(bomTypes) == 0 {
		return nil
	}
	return &scan.BOMOptions{Types: bomTypes, Format: bomFormat, Output: bomOutput, Target: target}
}

// reportWriter returns where the findings report goes: stderr when the BOM
// is written to stdout (--bom-output -) and --output is not set, so the two
// do not mix; w otherwise. It stays out of cmdutil.ResolveOutput, which also
// serves scan sbom and supply-chain check, commands that build no BOMs.
func reportWriter(w io.Writer) io.Writer {
	if len(bomTypes) > 0 && bomOutput == scan.BOMOutputStdout && outputFile == "" {
		return os.Stderr
	}
	return w
}

// bomExit returns the scan's exit error: err from formatScanResult wins, a
// --fail-on exit included; otherwise a failed BOM download gives
// ErrBOMIncomplete, which exits 2.
func bomExit(result *model.ScanResult, err error) error {
	if err != nil {
		return err
	}
	if result == nil || len(result.BOMFailures) == 0 {
		return nil
	}
	labels := make([]string, 0, len(result.BOMFailures))
	for _, t := range result.BOMFailures {
		labels = append(labels, scan.BOMLabel(t))
	}
	return &output.ErrBOMIncomplete{ScanID: result.ScanID, Labels: labels}
}

// formatScanResult writes result through formatter and returns the --fail-on
// exit decision. --min-severity is display-only: only the copy handed to the
// formatter is filtered, and CheckExit always evaluates the original result,
// so hiding findings can never weaken the CI gate. SARIF always gets every
// finding: GitHub code scanning closes alerts missing from an upload as fixed,
// so filtering it would rewrite alert history. CheckExit runs last because it
// also flushes stdout.
func formatScanResult(formatter output.Formatter, result *model.ScanResult, w io.Writer, opts output.FormatOptions, minSeverity string, failOnSeverities []string) error {
	if _, isSARIF := formatter.(*output.SARIFFormatter); isSARIF && minSeverity != "" {
		cli.PrintWarning("--min-severity is ignored for SARIF output; all findings are included")
		minSeverity = ""
	}

	display, err := output.FilterByMinSeverity(result, minSeverity)
	if err != nil {
		return fmt.Errorf("failed to filter findings: %w", err)
	}
	if err := formatter.FormatWithOptions(display, w, opts); err != nil {
		return fmt.Errorf("failed to format output: %w", err)
	}

	if hidden := output.FailingCount(result, failOnSeverities) - output.FailingCount(display, failOnSeverities); hidden > 0 {
		cli.PrintWarning(output.HiddenFailingWarning(hidden, minSeverity))
	}

	if err := output.CheckExit(result, failOnSeverities, exitCode); err != nil {
		return err
	}
	// A recorded run the history truncated passes --fail-on only on levels
	// its kept findings decide.
	return output.CheckTruncation(result, failOnSeverities)
}

// runScanShorthand runs `armis-cli scan <path>` exactly as `armis-cli scan repo
// <path>`. With no path it prints the help, as `scan` always has, unless flags
// were given: then it fails, so a CI step like `armis-cli scan --project x`
// cannot pass without scanning anything.
func runScanShorthand(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		if anyFlagChanged(cmd) {
			return fmt.Errorf("missing scan target: name the folder to scan (for example 'armis-cli scan .'), " +
				"or use 'armis-cli scan repo|image|sbom|status'")
		}
		return cmd.Help()
	}

	err := runRepoScan(cmd, args)

	// A target the repository scan cannot find is most likely a mistyped
	// subcommand or an image reference, so say which. Any lookup failure but a
	// permission error counts: on Windows the ':' of an image reference makes
	// the name invalid rather than missing. Only a tag or digest ("nginx:1.27")
	// that really parses as an image reference gets the image hint, so a
	// missing folder or a Windows path (`C:\code\app`) does not.
	var targetErr *scanTargetError
	if errors.As(err, &targetErr) && !os.IsPermission(targetErr.Err) {
		if suggestions := cmd.SuggestionsFor(args[0]); len(suggestions) > 0 {
			return fmt.Errorf("%w (did you mean 'armis-cli scan %s'?)", err, suggestions[0])
		}
		if strings.ContainsAny(args[0], ":@") && image.IsImageReference(args[0]) {
			return fmt.Errorf("%w (to scan a container image, use 'armis-cli scan image %s')", err, args[0])
		}
	}
	return err
}

// anyFlagChanged reports whether any flag of cmd (including inherited ones)
// was set on the command line. Values that came from environment-derived
// defaults do not count.
func anyFlagChanged(cmd *cobra.Command) bool {
	changed := false
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if f.Changed {
			changed = true
		}
	})
	return changed
}

func init() {
	// `scan <path>` is a repository scan; see runScanShorthand. Wired here
	// rather than in the literal, which would make scanCmd's initializer
	// depend on functions that reference it.
	scanCmd.Args = cobra.MaximumNArgs(1)
	scanCmd.RunE = runScanShorthand
	// cobra only applies its default distance (2) on its own unknown-command
	// path; runScanShorthand calls SuggestionsFor directly, so set it here.
	scanCmd.SuggestionsMinimumDistance = 2
	// `scan <TAB>` completes the subcommand names (cobra adds them) and paths.
	// Not ShellCompDirectiveFilterDirs: the bash and zsh scripts read the first
	// completion as the folder to list, which here is a subcommand name, so
	// nothing would complete.
	scanCmd.ValidArgsFunction = func(_ *cobra.Command, args []string, _ string) ([]cobra.Completion, cobra.ShellCompDirective) {
		if len(args) > 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return nil, cobra.ShellCompDirectiveDefault
	}
	addRepoScanFlags(scanCmd)

	// Scan-output flags. These were previously root persistent flags but only
	// apply to the scan subtree, so they are scoped here to keep them out of the
	// --help of non-scan commands (hook, supply-chain, install, agent-detection).
	// Defaults and env bindings are preserved verbatim from their former root
	// registrations. `supply-chain check` re-registers the subset it consumes
	// locally (see supply_chain_check.go), since it is a sibling of scan.
	scanCmd.PersistentFlags().StringVarP(&format, "format", "f", getEnvOrDefault("ARMIS_FORMAT", "human"), "Output format: human, json, sarif, junit")
	addUploadFlags(scanCmd)
	scanCmd.PersistentFlags().StringSliceVar(&failOn, "fail-on", defaultFailOn(), failOnUsage)
	scanCmd.PersistentFlags().IntVar(&exitCode, "exit-code", 1, "Exit code when --fail-on triggers")
	scanCmd.PersistentFlags().StringVar(&minSeverity, "min-severity", "", "Only display findings at or above this severity: INFO, LOW, MEDIUM, HIGH, CRITICAL (display only: --fail-on still evaluates all findings, and SARIF output always includes them all)")
	// armis:ignore cwe:770 cwe:401 reason:--page-limit is bounded to 1-1000 by validatePageLimit (root.go); every consumer (scan_repo.go, scan_image.go) reads it via getPageLimit() which validates before the value reaches any pagination sink. This is the flag declaration, not a sink.
	scanCmd.PersistentFlags().IntVar(&pageLimit, "page-limit", getEnvOrDefaultInt("ARMIS_PAGE_LIMIT", 500), "Results page size for pagination (range: 1-1000)")
	// Tab-completion for the relocated enumerated flags now lives with the flags.
	_ = scanCmd.RegisterFlagCompletionFunc("format", formatCompletions())
	_ = scanCmd.RegisterFlagCompletionFunc("fail-on", severityCompletions())
	_ = scanCmd.RegisterFlagCompletionFunc("min-severity", severityCompletions())

	scanCmd.PersistentFlags().BoolVar(&includeTests, "include-tests", false, includeTestsUsage)
	scanCmd.PersistentFlags().BoolVar(&includeNonExploitable, "include-non-exploitable", false, "Show low/medium exploitability findings (hidden by default; high and ungraded findings always shown)")
	scanCmd.PersistentFlags().StringVar(&groupBy, "group-by", "none", "Group findings by: none, cwe, severity, file")
	_ = scanCmd.RegisterFlagCompletionFunc("group-by", fixedCompletions(validGroupBy, map[string]string{
		"none":     "No grouping (default)",
		"cwe":      "Group findings by CWE identifier",
		"severity": "Group findings by severity level",
		"file":     "Group findings by file path",
	}))
	scanCmd.PersistentFlags().BoolVar(&generateSBOM, "sbom", false, "Generate Software Bill of Materials (SBOM); serialization set by --sbom-format")
	scanCmd.PersistentFlags().StringVar(&sbomFormat, "sbom-format", scan.SBOMFormatCycloneDX, "SBOM serialization format: cyclonedx, spdx (requires --sbom)")
	_ = scanCmd.RegisterFlagCompletionFunc("sbom-format", fixedCompletions(validSBOMFormats, map[string]string{
		scan.SBOMFormatCycloneDX: "CycloneDX JSON (default)",
		scan.SBOMFormatSPDX:      "SPDX 2.3 JSON",
	}))
	scanCmd.PersistentFlags().BoolVar(&generateVEX, "vex", false, "Generate Vulnerability Exploitability eXchange (VEX) document")
	scanCmd.PersistentFlags().StringVar(&sbomOutput, "sbom-output", "", "Output file path for SBOM (default: .armis/<artifact>-sbom.json)")
	scanCmd.PersistentFlags().StringVar(&vexOutput, "vex-output", "", "Output file path for VEX (default: .armis/<artifact>-vex.json)")
	scanCmd.PersistentFlags().StringSliceVar(&bomTypes, "bom", nil, "Download BOMs of these types, comma-separated or repeated: sbom, aibom, cbom, all (combined); BOM generation must be enabled for your tenant")
	scanCmd.PersistentFlags().StringVar(&bomFormat, "bom-format", scan.BOMFormatCycloneDX17, "BOM format: cyclonedx-1.7, cyclonedx-1.6, spdx-2.3, spdx-3.0.1, or the aliases cyclonedx, spdx (requires --bom; BOM generation must be enabled for your tenant)")
	_ = scanCmd.RegisterFlagCompletionFunc("bom", bomTypeCompletions())
	_ = scanCmd.RegisterFlagCompletionFunc("bom-format", bomFormatCompletions())
	scanCmd.PersistentFlags().StringVar(&bomOutput, "bom-output", "", "Directory for BOM files, or - to write one BOM to stdout (default: .armis; requires --bom; BOM generation must be enabled for your tenant)")
	scanCmd.PersistentFlags().BoolVar(&summaryTop, "summary-top", false, "Display summary at the top of output (before findings)")
	scanCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "Write output to file (auto-detects format from extension: .json, .sarif, .xml)")
	if rootCmd != nil {
		rootCmd.AddCommand(scanCmd)
	}
}
