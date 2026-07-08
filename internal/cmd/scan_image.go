package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/api"
	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/cmd/cmdutil"
	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/scan"
	"github.com/ArmisSecurity/armis-cli/internal/scan/image"
	"github.com/ArmisSecurity/armis-cli/internal/util"
	"github.com/spf13/cobra"
)

var tarballPath string
var pullPolicy string

var scanImageCmd = &cobra.Command{
	Use:   "image [image-name]",
	Short: "Scan a container image",
	Long:  `Scan a local or remote container image for security vulnerabilities.`,
	Example: `  $ armis-cli scan image nginx:latest
  $ armis-cli scan image myapp:v1.0 --format json
  $ armis-cli scan image --tarball ./image.tar
  $ armis-cli scan image alpine:3.18 --sbom --vex --fail-on HIGH,CRITICAL`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Validate --pull before auth so a bad value (e.g. "badvalue") surfaces as a
		// flag error rather than hiding behind an auth failure. This mirrors the
		// allowlist in determinePullBehavior, which only runs after auth + the docker
		// check; "" is excluded here because the flag default is "missing".
		//
		// Only validate on the image-name path: --pull is documented as "Ignored
		// when --tarball is used" (tarball scans never pull), so rejecting a bad
		// --pull alongside --tarball would contradict the flag's contract.
		if tarballPath == "" {
			switch pullPolicy {
			case "always", "missing", "never":
				// valid
			default:
				return fmt.Errorf("invalid --pull value %q: must be one of [always missing never]", pullPolicy)
			}
		}

		if tarballPath == "" && len(args) == 0 {
			return fmt.Errorf("missing target: specify an image name or use --tarball")
		}

		// Validate tarball path exists before making network calls
		if tarballPath != "" {
			// armis:ignore cwe:22 reason:os.Stat is read-only existence check; path sanitized via util.SanitizePath() before filesystem write
			// armis:ignore cwe:367 reason:TOCTOU benign here; tarball read later via docker/podman, not direct open after stat
			info, err := os.Stat(tarballPath)
			if err != nil {
				if os.IsNotExist(err) {
					return fmt.Errorf("tarball does not exist: %s", tarballPath)
				}
				return fmt.Errorf("cannot access tarball %s: %w", tarballPath, err)
			}
			if info.IsDir() {
				return fmt.Errorf("tarball path is a directory, not a file: %s", tarballPath)
			}
		}

		// Surface a missing container runtime before auth. Scanning by image name
		// exports via Docker/Podman, so a dev with no runtime would otherwise hit
		// the auth error first and never learn the real blocker. --tarball bypasses
		// the daemon, so skip this check on that path.
		if tarballPath == "" && !image.IsDockerAvailable() {
			return image.ErrRuntimeNotFound
		}

		authProvider, err := getAuthProvider(cmd.Context())
		if err != nil {
			return err
		}
		// Defensive nil-check. getAuthProvider returns (nil, err) on
		// failure and (non-nil, nil) on success — the explicit guard
		// here exists so a future refactor can't silently slip a nil
		// past the err check and crash subsequent calls.
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
		scanner := image.NewScanner(client, noProgress, tid, limit, includeTests, scanTimeoutDuration, includeNonExploitable).
			WithPullPolicy(pullPolicy)

		// --sbom-output/--vex-output misuse is warned about in scan.PersistentPreRunE
		// (before auth), so no warning is emitted here.

		// Configure SBOM/VEX options if any flags are set
		if generateSBOM || generateVEX {
			sbomVEXOpts := &scan.SBOMVEXOptions{
				GenerateSBOM: generateSBOM,
				GenerateVEX:  generateVEX,
				SBOMOutput:   sbomOutput,
				VEXOutput:    vexOutput,
			}
			scanner = scanner.WithSBOMVEXOptions(sbomVEXOpts)
		}

		ctx, cancel := NewSignalContext()
		defer cancel()

		var result *model.ScanResult

		// Warn if both tarball and image name are provided
		if tarballPath != "" && len(args) > 0 {
			cli.PrintWarning("both --tarball and image name provided; using tarball (image name ignored)")
		}

		if tarballPath != "" {
			// armis:ignore cwe:22 reason:tarballPath is immediately sanitized by SanitizePath; only sanitizedPath is used
			sanitizedPath, pathErr := util.SanitizePath(tarballPath)
			if pathErr != nil {
				return fmt.Errorf("invalid tarball path: %w", pathErr)
			}
			result, err = scanner.ScanTarball(ctx, sanitizedPath)
			if err != nil {
				return handleScanError(ctx, err)
			}
		} else {
			// armis:ignore cwe:20 reason:imageName validated by distribution/reference.ParseNormalizedNamed in ScanImage
			imageName := args[0]
			result, err = scanner.ScanImage(ctx, imageName) // armis:ignore cwe:20 reason:validated by reference.ParseNormalizedNamed in ScanImage
			if err != nil {
				return handleScanError(ctx, err)
			}
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
			RepoPath:         "",
			Debug:            debug,
			SummaryTop:       summaryTop,
			FailOnSeverities: failOnSeverities,
		}

		if err := formatter.FormatWithOptions(result, outputCfg.Writer, opts); err != nil {
			return fmt.Errorf("failed to format output: %w", err)
		}

		return output.CheckExit(result, failOnSeverities, exitCode)
	},
}

func init() {
	scanImageCmd.Flags().StringVar(&tarballPath, "tarball", "", "Path to a container image tarball")
	scanImageCmd.Flags().StringVar(&pullPolicy, "pull", "missing", "Image pull policy: 'always', 'missing' (default), or 'never'. Ignored when --tarball is used")
	scanCmd.AddCommand(scanImageCmd)
}
