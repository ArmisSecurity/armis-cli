// Package image provides container image scanning functionality.
package image

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/api"
	"github.com/ArmisSecurity/armis-cli/internal/model"
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
	sbomVEXOpts           *scan.SBOMVEXOptions
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
	}
}

// WithPollInterval sets a custom poll interval for the scanner (used for testing).
func (s *Scanner) WithPollInterval(d time.Duration) *Scanner {
	s.pollInterval = d
	return s
}

// WithSBOMVEXOptions sets SBOM and VEX generation options.
func (s *Scanner) WithSBOMVEXOptions(opts *scan.SBOMVEXOptions) *Scanner {
	s.sbomVEXOpts = opts
	return s
}

// ScanImage scans a container image by name.
func (s *Scanner) ScanImage(ctx context.Context, imageName string) (*model.ScanResult, error) {
	normalised, err := validateImageName(imageName)
	if err != nil {
		return nil, err
	}
	imageName = normalised

	if !isDockerAvailable() {
		return nil, fmt.Errorf("docker is not available. Please install Docker or Podman")
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

	fmt.Printf("Exporting image: %s\n", imageName)
	if err := s.exportImage(ctx, imageName, tmpFileName); err != nil {
		return nil, fmt.Errorf("failed to export image: %w", err)
	}

	return s.ScanTarball(ctx, tmpFileName)
}

// ScanTarball scans a container image from a tarball file.
func (s *Scanner) ScanTarball(ctx context.Context, tarballPath string) (*model.ScanResult, error) {
	// Validate path for defense-in-depth (CLI layer also validates)
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

	file, err := os.Open(tarballPath) // #nosec G304 - tarball path is user-provided input
	if err != nil {
		return nil, fmt.Errorf("failed to open tarball: %w", err)
	}
	defer file.Close() //nolint:errcheck // file opened for reading

	uploadSpinner := progress.NewSpinnerWithContext(ctx, "Uploading image...", s.noProgress)
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
	fmt.Fprintf(os.Stderr, "Scan initiated with ID: %s\n\n", scanID)

	spinner := progress.NewSpinnerWithContext(ctx, "Waiting for scan to complete...", s.noProgress)
	spinner.Start()
	defer spinner.Stop()

	_, err = s.client.WaitForIngest(ctx, s.tenantID, scanID, s.pollInterval, s.timeout)
	elapsed := spinner.GetElapsed()
	if err != nil {
		return nil, fmt.Errorf("failed to wait for scan: %w", err)
	}

	spinner.Stop()
	fmt.Fprintf(os.Stderr, "Scan completed in %s. Fetching results...\n", formatElapsed(elapsed))

	findings, err := s.client.FetchAllNormalizedResults(ctx, s.tenantID, scanID, s.pageLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch results: %w", err)
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
			fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
		}
	}

	result := buildScanResult(scanID, findings, s.client.IsDebug(), s.includeNonExploitable)
	return result, nil
}

func (s *Scanner) exportImage(ctx context.Context, imageName, outputPath string) error {
	dockerCmd := getDockerCommand()
	if err := validateDockerCommand(dockerCmd); err != nil {
		return err
	}

	var pullCmd, saveCmd *exec.Cmd
	switch dockerCmd {
	case dockerBinary:
		pullCmd = exec.CommandContext(ctx, "docker", "pull", imageName)
		saveCmd = exec.CommandContext(ctx, "docker", "save", "-o", outputPath, imageName)
	case podmanBinary:
		pullCmd = exec.CommandContext(ctx, "podman", "pull", imageName)
		saveCmd = exec.CommandContext(ctx, "podman", "save", "-o", outputPath, imageName)
	default:
		return fmt.Errorf("unsupported container CLI: %q", dockerCmd)
	}

	pullCmd.Stdout = os.Stdout
	pullCmd.Stderr = os.Stderr
	if err := pullCmd.Run(); err != nil {
		return fmt.Errorf("failed to pull image: %w", err)
	}

	saveCmd.Stdout = os.Stdout
	saveCmd.Stderr = os.Stderr
	if err := saveCmd.Run(); err != nil {
		return fmt.Errorf("failed to save image: %w", err)
	}

	return nil
}

func isDockerAvailable() bool {
	cmd := exec.Command("docker", "version")
	if err := cmd.Run(); err == nil {
		return true
	}

	cmd = exec.Command("podman", "version")
	if err := cmd.Run(); err == nil {
		return true
	}

	return false
}

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

		if !includeNonExploitable && shouldFilterByExploitability(nf.NormalizedTask.Labels) {
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
			rawJSON, err := json.Marshal(debugCopy)
			if err != nil {
				fmt.Fprintf(os.Stderr, "\n=== DEBUG: Finding #%d JSON Marshal Error: %v ===\n\n", i+1, err)
			} else {
				fmt.Fprintf(os.Stderr, "\n=== DEBUG: Finding #%d Raw JSON ===\n%s\n=== END DEBUG ===\n\n", i+1, string(rawJSON))
			}
		}

		finding := model.Finding{
			ID:          nf.NormalizedTask.FindingID,
			Severity:    mapSeverity(nf.NormalizedRemediation.ToolSeverity),
			Description: nf.NormalizedRemediation.Description,
			CVEs:        nf.NormalizedRemediation.VulnerabilityTypeMetadata.CVEs,
			CWEs:        nf.NormalizedRemediation.VulnerabilityTypeMetadata.CWEs,
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

		if finding.FindingCategory != "" {
			finding.Title = util.FormatCategory(finding.FindingCategory)
		} else {
			finding.Title = finding.Description
		}

		findings = append(findings, finding)
	}

	return findings, filteredCount
}

func shouldFilterByExploitability(labels []model.Label) bool {
	var scannerCodeMatch bool
	var exploitableFalse bool

	for _, label := range labels {
		desc := strings.ToLower(strings.TrimSpace(label.Description))
		value := strings.ToLower(strings.TrimSpace(label.Value))

		if desc == "scanner code" && value == "38295677" {
			scannerCodeMatch = true
		}
		if desc == "exploitable" && (value == "false" || value == "0") {
			exploitableFalse = true
		}
	}

	return scannerCodeMatch && exploitableFalse
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

func mapSeverity(toolSeverity string) model.Severity {
	switch strings.ToUpper(toolSeverity) {
	case "CRITICAL":
		return model.SeverityCritical
	case "HIGH":
		return model.SeverityHigh
	case "MEDIUM":
		return model.SeverityMedium
	case "LOW":
		return model.SeverityLow
	default:
		return model.SeverityInfo
	}
}

func formatElapsed(d time.Duration) string {
	d = d.Round(time.Second)
	minutes := int(d.Minutes())
	seconds := int(d.Seconds()) % 60
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}
