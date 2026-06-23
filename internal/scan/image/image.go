// Package image provides container image scanning functionality.
package image

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/api"
	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/progress"
	"github.com/ArmisSecurity/armis-cli/internal/scan"
	"github.com/ArmisSecurity/armis-cli/internal/util"
)

const (
	// MaxImageSize is the maximum allowed size for container images.
	MaxImageSize = 5 * 1024 * 1024 * 1024
	dockerBinary = "docker"
	podmanBinary = "podman"
)

// ErrRuntimeNotFound is returned when neither Docker nor Podman is available to
// export an image. The message names the problem, the cause, and the fixes:
// install a runtime or start its daemon, or bypass the daemon entirely with --tarball.
var ErrRuntimeNotFound = errors.New("container runtime not found or not running: install Docker (https://docs.docker.com/get-docker/) or Podman (https://podman.io) and ensure the daemon is running; or use --tarball ./image.tar to scan a pre-exported image")

// Scanner scans container images for security vulnerabilities.
type Scanner struct {
	client                *api.Client
	noProgress            bool
	tenantID              string
	pageLimit             int
	includeTests          bool
	timeout               time.Duration
	includeNonExploitable bool
	pollInterval          time.Duration
	fetchRetryInterval    time.Duration
	sbomVEXOpts           *scan.SBOMVEXOptions
	pullPolicy            string // "always", "missing", "never"
}

// NewScanner creates a new image scanner with the given configuration.
func NewScanner(client *api.Client, noProgress bool, tenantID string, pageLimit int, includeTests bool, timeout time.Duration, includeNonExploitable bool) *Scanner {
	return &Scanner{
		client:                client,
		noProgress:            noProgress,
		tenantID:              tenantID,
		pageLimit:             pageLimit,
		includeTests:          includeTests,
		timeout:               timeout,
		includeNonExploitable: includeNonExploitable,
		pollInterval:          5 * time.Second,
		fetchRetryInterval:    10 * time.Second,
	}
}

// WithPollInterval sets a custom poll interval for the scanner (used for testing).
func (s *Scanner) WithPollInterval(d time.Duration) *Scanner {
	s.pollInterval = d
	return s
}

// WithFetchRetryInterval sets a custom retry interval for result fetching (used for testing).
func (s *Scanner) WithFetchRetryInterval(d time.Duration) *Scanner {
	s.fetchRetryInterval = d
	return s
}

// WithSBOMVEXOptions sets SBOM and VEX generation options.
func (s *Scanner) WithSBOMVEXOptions(opts *scan.SBOMVEXOptions) *Scanner {
	s.sbomVEXOpts = opts
	return s
}

// WithPullPolicy sets the image pull policy.
// Valid values: "always" (always pull), "missing" (pull if not local), "never" (require local).
func (s *Scanner) WithPullPolicy(policy string) *Scanner {
	s.pullPolicy = policy
	return s
}

// ScanImage scans a container image by name.
func (s *Scanner) ScanImage(ctx context.Context, imageName string) (*model.ScanResult, error) {
	normalised, err := validateImageName(imageName)
	if err != nil {
		return nil, err
	}
	imageName = normalised

	if !IsDockerAvailable() {
		return nil, ErrRuntimeNotFound
	}

	tmpFile, err := os.CreateTemp("", "armis-image-*.tar")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpFileName := tmpFile.Name()

	// Ensure cleanup always runs, even on context cancellation
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFileName)
	}()

	if err := s.exportImage(ctx, imageName, tmpFileName); err != nil {
		return nil, fmt.Errorf("failed to export image: %w", err)
	}

	return s.ScanTarball(ctx, tmpFileName)
}

// ScanTarball scans a container image from a tarball file.
func (s *Scanner) ScanTarball(ctx context.Context, tarballPath string) (*model.ScanResult, error) {
	// armis:ignore cwe:22 reason:SanitizePath IS the path traversal prevention; rejects invalid paths before use
	sanitizedPath, err := util.SanitizePath(tarballPath)
	if err != nil {
		return nil, fmt.Errorf("invalid tarball path: %w", err)
	}
	tarballPath = sanitizedPath

	info, err := os.Stat(tarballPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat tarball: %w", err)
	}

	if info.Size() > MaxImageSize {
		return nil, fmt.Errorf("tarball size (%d bytes) exceeds maximum allowed size (%d bytes)", info.Size(), MaxImageSize)
	}

	// armis:ignore cwe:22 reason:tarballPath sanitized by util.SanitizePath on line 121; rejects traversal before reaching here
	file, err := os.Open(tarballPath) //nolint:gosec // G304: path sanitized above
	if err != nil {                   // armis:ignore cwe:22 reason:tarballPath sanitized by util.SanitizePath above
		return nil, fmt.Errorf("failed to open tarball: %w", err)
	}
	defer file.Close() //nolint:errcheck // file opened for reading

	uploadSpinner := progress.NewSpinnerWithContext(ctx, "Uploading to Armis Cloud...", s.noProgress)
	uploadSpinner.Start()
	defer uploadSpinner.Stop()

	ingestOpts := api.IngestOptions{
		TenantID:     s.tenantID,
		ArtifactType: "image",
		Filename:     filepath.Base(tarballPath),
		Data:         file,
		Size:         info.Size(),
	}
	if s.sbomVEXOpts != nil {
		ingestOpts.GenerateSBOM = s.sbomVEXOpts.GenerateSBOM
		ingestOpts.GenerateVEX = s.sbomVEXOpts.GenerateVEX
	}

	scanID, err := s.client.StartIngest(ctx, ingestOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to upload image: %w", err)
	}

	uploadSpinner.Stop()
	styles := output.GetStyles()
	fmt.Fprintf(os.Stderr, "%s %s\n\n",
		styles.MutedText.Render("Scan initiated with ID:"),
		styles.ScanID.Render(scanID))

	spinner := progress.NewSpinnerWithContext(ctx, "Scanning for security issues...", s.noProgress)
	spinner.Start()
	defer spinner.Stop()

	_, err = s.client.WaitForIngest(ctx, s.tenantID, scanID, s.pollInterval, s.timeout,
		func(status model.IngestStatusData) {
			spinner.Update(scan.FormatScanStatus(status.ScanStatus, "Scanning for security issues..."))
		})
	elapsed := spinner.GetElapsed()
	if err != nil {
		return nil, fmt.Errorf("failed to wait for scan: %w", err)
	}

	spinner.Stop()
	fmt.Fprintf(os.Stderr, "%s %s\n\n",
		styles.MutedText.Render("Scan completed in"),
		styles.Duration.Render(scan.FormatElapsed(elapsed)))

	fetchSpinner := progress.NewSpinnerWithContext(ctx, "Retrieving results...", s.noProgress)
	fetchSpinner.Start()

	var findings []model.NormalizedFinding
	const maxFetchRetries = 5
	for attempt := 1; attempt <= maxFetchRetries; attempt++ {
		findings, err = s.client.FetchAllNormalizedResults(ctx, s.tenantID, scanID, s.pageLimit)
		if err == nil {
			break
		}
		if !isRetryableError(err) {
			break
		}
		if attempt < maxFetchRetries {
			fetchSpinner.Update(fmt.Sprintf("Retrieving results (retry %d/%d)...", attempt, maxFetchRetries-1))
			time.Sleep(s.fetchRetryInterval)
		}
	}
	fetchSpinner.Stop()
	if err != nil {
		cli.PrintWarningf("Failed to retrieve results: %v", err)
		cli.PrintWarningf("Scan completed successfully. Results are available with scan ID: %s", scanID)
		return nil, &output.ErrResultsIncomplete{ScanID: scanID}
	}

	// Handle SBOM/VEX downloads if requested
	if s.sbomVEXOpts != nil && (s.sbomVEXOpts.GenerateSBOM || s.sbomVEXOpts.GenerateVEX) {
		// Extract artifact name from tarball path (remove extension)
		artifactName := filepath.Base(tarballPath)
		if ext := filepath.Ext(artifactName); ext != "" {
			artifactName = artifactName[:len(artifactName)-len(ext)]
		}
		downloader := scan.NewSBOMVEXDownloader(s.client, s.tenantID, s.sbomVEXOpts)
		if err := downloader.Download(ctx, scanID, artifactName); err != nil {
			// Log warning but don't fail the scan
			cli.PrintWarningf("%v", err)
		}
	}

	result := buildScanResult(scanID, findings, s.client.IsDebug(), s.includeNonExploitable)
	return result, nil
}

func (s *Scanner) exportImage(ctx context.Context, imageName, outputPath string) error {
	// Defense-in-depth: validate image name even though callers should have validated.
	// This prevents command injection even if this method is called from a new code path.
	normalised, err := validateImageName(imageName)
	if err != nil {
		return fmt.Errorf("invalid image name: %w", err)
	}
	imageName = normalised

	dockerCmd := getDockerCommand()
	if err := validateDockerCommand(dockerCmd); err != nil {
		return err
	}

	styles := output.GetStyles()

	// Determine pull behavior based on policy
	localExists := imageExistsLocally(ctx, dockerCmd, imageName)
	shouldPull, err := determinePullBehavior(s.pullPolicy, localExists)
	if err != nil {
		return fmt.Errorf("image %q: %w", imageName, err)
	}

	if shouldPull {
		fmt.Fprintf(os.Stderr, "%s %s...\n",
			styles.MutedText.Render("Pulling image"),
			styles.Bold.Render(imageName))

		// armis:ignore cwe:94 reason:dockerCmd from getDockerCommand (hardcoded docker/podman); imageName validated by validateImageName()
		// armis:ignore cwe:78 reason:dockerCmd validated by validateDockerCommand allowlist; imageName validated by validateImageName
		pullCmd := exec.CommandContext(ctx, dockerCmd, "pull", imageName) //nolint:gosec // G204: dockerCmd is validated, imageName is validated by validateImageName()
		pullCmd.Stdout = os.Stderr                                        // armis:ignore cwe:78 reason:dockerCmd and imageName validated by allowlist + validateImageName()
		pullCmd.Stderr = os.Stderr
		if err := pullCmd.Run(); err != nil {
			return fmt.Errorf("failed to pull image: %w", err)
		}
	} else {
		fmt.Fprintf(os.Stderr, "%s %s...\n",
			styles.MutedText.Render("Using local image"),
			styles.Bold.Render(imageName))
	}

	// armis:ignore cwe:94 reason:dockerCmd from getDockerCommand (hardcoded docker/podman); imageName validated by validateImageName()
	// armis:ignore cwe:78 reason:dockerCmd validated by validateDockerCommand allowlist; imageName validated by validateImageName; outputPath is temp file
	saveCmd := exec.CommandContext(ctx, dockerCmd, "save", "-o", outputPath, imageName) //nolint:gosec // G204: dockerCmd is validated, imageName is validated, outputPath is controlled
	saveCmd.Stdout = os.Stderr
	saveCmd.Stderr = os.Stderr
	if err := saveCmd.Run(); err != nil {
		return fmt.Errorf("failed to save image: %w", err)
	}

	return nil
}

// IsDockerAvailable reports whether a container runtime (Docker or Podman) is
// reachable on the host. Callers use it to fail fast before auth/network work
// when an image must be exported via the daemon.
// armis:ignore cwe:426 cwe:427 reason:exec.Command uses hardcoded binary constants (dockerBinary/podmanBinary); no untrusted path
func IsDockerAvailable() bool {
	cmd := exec.Command(dockerBinary, "version")
	if err := cmd.Run(); err == nil {
		return true
	}

	cmd = exec.Command(podmanBinary, "version")
	if err := cmd.Run(); err == nil {
		return true
	}

	return false
}

// armis:ignore cwe:426 reason:dockerBinary is a hardcoded constant ("docker"); no untrusted search path
func getDockerCommand() string {
	cmd := exec.Command(dockerBinary, "version")
	if err := cmd.Run(); err == nil {
		return dockerBinary
	}

	return podmanBinary
}

func validateDockerCommand(cmd string) error {
	if cmd != dockerBinary && cmd != podmanBinary {
		return fmt.Errorf("unsupported container engine: %s", cmd)
	}
	return nil
}

// imageExistsLocally checks if the image is available in the local container runtime.
// armis:ignore cwe:78 cwe:94 reason:dockerCmd validated by validateDockerCommand; imageName validated by validateImageName (defense-in-depth)
func imageExistsLocally(ctx context.Context, dockerCmd, imageName string) bool {
	if err := validateDockerCommand(dockerCmd); err != nil {
		return false
	}
	if _, err := validateImageName(imageName); err != nil {
		return false
	}
	// armis:ignore cwe:78 cwe:94 reason:dockerCmd validated by validateDockerCommand; imageName validated by validateImageName
	cmd := exec.CommandContext(ctx, dockerCmd, "image", "inspect", imageName) //nolint:gosec // G204: dockerCmd is validated, imageName is validated above
	cmd.Stdout = io.Discard                                                   // Suppress JSON output on successful inspect
	cmd.Stderr = io.Discard                                                   // Suppress "Error: no such image" noise
	return cmd.Run() == nil
}

// determinePullBehavior returns whether to pull and any error based on policy and local existence.
func determinePullBehavior(policy string, localExists bool) (shouldPull bool, err error) {
	switch policy {
	case "always":
		return true, nil
	case "never":
		if !localExists {
			return false, fmt.Errorf("image not found locally (pull policy is 'never')")
		}
		return false, nil
	case "missing", "":
		return !localExists, nil
	default:
		return false, fmt.Errorf("invalid pull policy %q: must be 'always', 'missing', or 'never'", policy)
	}
}

// isRetryableError returns true for transient errors (timeouts, network errors,
// 5xx server errors) and false for permanent errors (4xx, decode failures).
func isRetryableError(err error) bool {
	var apiErr *api.APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode >= 500
	}
	return errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err)
}

func buildScanResult(scanID string, normalizedFindings []model.NormalizedFinding, debug bool, includeNonExploitable bool) *model.ScanResult {
	findings, filteredCount := convertNormalizedFindings(normalizedFindings, debug, includeNonExploitable)

	summary := model.Summary{
		Total:                  len(findings),
		BySeverity:             make(map[model.Severity]int),
		ByType:                 make(map[model.FindingType]int),
		ByCategory:             make(map[string]int),
		FilteredNonExploitable: filteredCount,
	}

	for _, finding := range findings {
		summary.BySeverity[finding.Severity]++
		summary.ByType[finding.Type]++
		if finding.FindingCategory != "" {
			summary.ByCategory[finding.FindingCategory]++
		}
	}

	return &model.ScanResult{
		ScanID:   scanID,
		Status:   "completed",
		Findings: findings,
		Summary:  summary,
	}
}

func convertNormalizedFindings(normalizedFindings []model.NormalizedFinding, debug bool, includeNonExploitable bool) ([]model.Finding, int) {
	var findings []model.Finding
	filteredCount := 0

	for i, nf := range normalizedFindings {
		if isEmptyFinding(nf) {
			continue
		}

		if !includeNonExploitable && scan.ShouldFilterByExploitability(nf.NormalizedTask.Labels) {
			filteredCount++
			continue
		}

		if debug {
			// Create a sanitized copy for debug output to prevent secret exposure
			debugCopy := nf
			if debugCopy.NormalizedTask.ExtraData.CodeLocation.Snippet != nil {
				masked := util.MaskSecretInLine(*debugCopy.NormalizedTask.ExtraData.CodeLocation.Snippet)
				debugCopy.NormalizedTask.ExtraData.CodeLocation.Snippet = &masked
			}
			if len(debugCopy.NormalizedTask.ExtraData.CodeLocation.CodeSnippetLines) > 0 {
				debugCopy.NormalizedTask.ExtraData.CodeLocation.CodeSnippetLines =
					util.MaskSecretInLines(debugCopy.NormalizedTask.ExtraData.CodeLocation.CodeSnippetLines)
			}
			if debugCopy.NormalizedTask.ExtraData.Fix != nil {
				debugCopy.NormalizedTask.ExtraData.Fix = scan.MaskFixSecrets(debugCopy.NormalizedTask.ExtraData.Fix)
			}
			rawJSON, err := json.Marshal(debugCopy)
			if err != nil {
				fmt.Fprintf(os.Stderr, "\n=== DEBUG: Finding #%d JSON Marshal Error: %v ===\n\n", i+1, err)
			} else {
				fmt.Fprintf(os.Stderr, "\n=== DEBUG: Finding #%d Raw JSON ===\n%s\n=== END DEBUG ===\n\n", i+1, string(rawJSON))
			}
		}

		finding := model.Finding{
			ID:                      nf.NormalizedTask.FindingID,
			Severity:                scan.MapSeverity(nf.NormalizedRemediation.ToolSeverity),
			Description:             nf.NormalizedRemediation.Description,
			CVEs:                    nf.NormalizedRemediation.VulnerabilityTypeMetadata.CVEs,
			CWEs:                    nf.NormalizedRemediation.VulnerabilityTypeMetadata.CWEs,
			OWASPCategories:         nf.NormalizedRemediation.VulnerabilityTypeMetadata.OWASPCategories,
			LongDescriptionMarkdown: nf.NormalizedRemediation.VulnerabilityTypeMetadata.LongDescriptionMarkdown,
			URLs:                    nf.NormalizedRemediation.VulnerabilityTypeMetadata.URLs,
		}

		if finding.Description == "" {
			if nf.NormalizedRemediation.VulnerabilityTypeMetadata.LongDescriptionMarkdown != "" {
				finding.Description = nf.NormalizedRemediation.VulnerabilityTypeMetadata.LongDescriptionMarkdown
			} else if nf.NormalizedTask.LongDescription != nil {
				finding.Description = *nf.NormalizedTask.LongDescription
			}
		}

		finding.Description = cleanDescription(finding.Description)

		if nf.NormalizedRemediation.FindingCategory != nil {
			if category, ok := nf.NormalizedRemediation.FindingCategory.(string); ok {
				finding.FindingCategory = category
			}
		}

		loc := nf.NormalizedTask.ExtraData.CodeLocation
		if loc.FileName != nil {
			finding.File = *loc.FileName
		}
		if loc.StartLine != nil {
			finding.StartLine = *loc.StartLine
		}
		if loc.EndLine != nil {
			finding.EndLine = *loc.EndLine
		}
		if loc.StartCol != nil {
			finding.StartColumn = *loc.StartCol
		}
		if loc.EndCol != nil {
			finding.EndColumn = *loc.EndCol
		}

		if len(loc.CodeSnippetLines) > 0 {
			finding.CodeSnippet = strings.Join(loc.CodeSnippetLines, "\n")
		} else if loc.Snippet != nil {
			finding.CodeSnippet = *loc.Snippet
		}

		if loc.SnippetStartLine != nil {
			finding.SnippetStartLine = *loc.SnippetStartLine
		}

		// Extract fix data if present
		if nf.NormalizedTask.ExtraData.Fix != nil {
			finding.Fix = nf.NormalizedTask.ExtraData.Fix
		}

		// Extract validation data if present
		if nf.NormalizedTask.ExtraData.FindingValidation != nil {
			finding.Validation = nf.NormalizedTask.ExtraData.FindingValidation
		}

		finding.Type = scan.DeriveFindingType(
			len(nf.NormalizedRemediation.VulnerabilityTypeMetadata.CVEs) > 0,
			loc.HasSecret,
			finding.FindingCategory,
		)

		if loc.HasSecret && finding.CodeSnippet != "" {
			finding.CodeSnippet = util.MaskSecretInLine(finding.CodeSnippet)
		}

		// Mask secrets in fix data to prevent leaking secrets through proposed fixes
		if loc.HasSecret && finding.Fix != nil {
			finding.Fix = scan.MaskFixSecrets(finding.Fix)
		}

		finding.Title = generateFindingTitle(&finding)

		findings = append(findings, finding)
	}

	return findings, filteredCount
}

func cleanDescription(desc string) string {
	lines := strings.Split(desc, "\n")
	var cleaned []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Code_location -") ||
			strings.HasPrefix(line, "Code Blob -") ||
			strings.HasPrefix(line, "Confidence -") {
			continue
		}
		if line != "" {
			cleaned = append(cleaned, line)
		}
	}

	return strings.Join(cleaned, " ")
}

func isEmptyFinding(nf model.NormalizedFinding) bool {
	hasDescription := nf.NormalizedRemediation.Description != "" ||
		nf.NormalizedRemediation.VulnerabilityTypeMetadata.LongDescriptionMarkdown != "" ||
		(nf.NormalizedTask.LongDescription != nil && *nf.NormalizedTask.LongDescription != "")

	hasCVEsOrCWEs := len(nf.NormalizedRemediation.VulnerabilityTypeMetadata.CVEs) > 0 ||
		len(nf.NormalizedRemediation.VulnerabilityTypeMetadata.CWEs) > 0

	hasCategory := nf.NormalizedRemediation.FindingCategory != nil

	return !hasDescription && !hasCVEsOrCWEs && !hasCategory
}

// generateFindingTitle creates a descriptive title for SARIF output.
// Delegates to the shared implementation in the scan package.
func generateFindingTitle(finding *model.Finding) string {
	return scan.GenerateFindingTitle(finding)
}
