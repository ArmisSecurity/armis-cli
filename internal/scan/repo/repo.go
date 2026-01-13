// Package repo provides repository scanning functionality.
package repo

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/api"
	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/progress"
	"github.com/ArmisSecurity/armis-cli/internal/scan"
	"github.com/ArmisSecurity/armis-cli/internal/util"
)

// MaxRepoSize is the maximum allowed size for repositories.
const MaxRepoSize = 2 * 1024 * 1024 * 1024

// Scanner scans repositories for security vulnerabilities.
type Scanner struct {
	client                *api.Client
	noProgress            bool
	tenantID              string
	pageLimit             int
	includeTests          bool
	timeout               time.Duration
	includeNonExploitable bool
	pollInterval          time.Duration
}

// NewScanner creates a new repository scanner with the given configuration.
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

// Scan scans a repository at the given path.
func (s *Scanner) Scan(ctx context.Context, path string) (*model.ScanResult, error) {
	// Validate path to prevent path traversal
	if _, err := util.SanitizePath(path); err != nil {
		return nil, fmt.Errorf("invalid repository path: %w", err)
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path: %w", err)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat path: %w", err)
	}

	if !info.IsDir() {
		return nil, fmt.Errorf("path is not a directory: %s", absPath)
	}

	ignoreMatcher, err := LoadIgnorePatterns(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load ignore patterns: %w", err)
	}

	size, err := calculateDirSize(absPath, s.includeTests, ignoreMatcher)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate directory size: %w", err)
	}

	if size > MaxRepoSize {
		return nil, fmt.Errorf("directory size (%d bytes) exceeds maximum allowed size (%d bytes)", size, MaxRepoSize)
	}

	pr, pw := io.Pipe()

	spinner := progress.NewSpinnerWithContext(ctx, "Creating a compressed archive...", s.noProgress)
	spinner.Start()
	defer spinner.Stop()

	errChan := make(chan error, 1)
	go func() {
		defer pw.Close() //nolint:errcheck // signals EOF to reader
		errChan <- s.tarGzDirectory(absPath, pw, ignoreMatcher)
	}()

	time.Sleep(500 * time.Millisecond)
	spinner.Update("Uploading archive to Armis Cloud...")

	scanID, err := s.client.StartIngest(ctx, s.tenantID, "repo", filepath.Base(absPath)+".tar.gz", pr, size)
	if err != nil {
		return nil, fmt.Errorf("failed to upload repository: %w", err)
	}

	if tarErr := <-errChan; tarErr != nil {
		return nil, fmt.Errorf("failed to tar directory: %w", tarErr)
	}

	spinner.Stop()
	fmt.Fprintf(os.Stderr, "Scan initiated with ID: %s\n\n", scanID)

	analysisSpinner := progress.NewSpinnerWithContext(ctx, "Analyzing code for vulnerabilities...", s.noProgress)
	analysisSpinner.Start()
	defer analysisSpinner.Stop()

	_, err = s.client.WaitForIngest(ctx, s.tenantID, scanID, s.pollInterval, s.timeout)
	elapsed := analysisSpinner.GetElapsed()
	analysisSpinner.Stop()
	if err != nil {
		return nil, fmt.Errorf("failed to wait for scan: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Analysis completed in %s\n\n", formatElapsed(elapsed))

	fetchSpinner := progress.NewSpinnerWithContext(ctx, "Fetching scan results...", s.noProgress)
	fetchSpinner.Start()
	defer fetchSpinner.Stop()

	findings, err := s.client.FetchAllNormalizedResults(ctx, s.tenantID, scanID, s.pageLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch results: %w", err)
	}

	result := buildScanResult(scanID, findings, s.client.IsDebug(), s.includeNonExploitable)
	return result, nil
}

func (s *Scanner) tarGzDirectory(sourcePath string, writer io.Writer, ignoreMatcher *IgnoreMatcher) (err error) {
	gzWriter := gzip.NewWriter(writer)
	defer func() {
		if closeErr := gzWriter.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	tarWriter := tar.NewWriter(gzWriter)
	defer func() {
		if closeErr := tarWriter.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	return filepath.Walk(sourcePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(sourcePath, path)
		if err != nil {
			return err
		}

		if ignoreMatcher != nil && ignoreMatcher.Match(relPath, info.IsDir()) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if shouldSkip(path, info, s.includeTests) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip symlinks to avoid security risks (symlinks pointing outside repo)
		// and potential issues (broken symlinks, loops)
		if info.Mode()&os.ModeSymlink != 0 {
			fmt.Fprintf(os.Stderr, "Warning: skipping symlink %s\n", relPath)
			return nil
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}

		// Use forward slashes for tar paths (standard convention for cross-platform compatibility)
		header.Name = filepath.ToSlash(relPath)

		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}

		if !info.IsDir() {
			file, err := os.Open(path) // #nosec G304 - path is from filepath.Walk within repo
			if err != nil {
				return err
			}

			_, copyErr := io.Copy(tarWriter, file)
			closeErr := file.Close()

			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		}

		return nil
	})
}

func calculateDirSize(path string, includeTests bool, ignoreMatcher *IgnoreMatcher) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(path, filePath)
		if err != nil {
			return err
		}

		if ignoreMatcher != nil && ignoreMatcher.Match(relPath, info.IsDir()) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if shouldSkip(filePath, info, includeTests) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip symlinks for consistency with tarGzDirectory
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}

		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}

func shouldSkip(path string, info os.FileInfo, includeTests bool) bool {
	name := info.Name()

	skipDirs := []string{
		".git", ".svn", ".hg",
		"node_modules", "vendor", "venv", ".venv",
		"__pycache__", ".pytest_cache",
		"target", "build", "dist", ".next",
		".idea", ".vscode",
	}

	if !includeTests {
		skipDirs = append(skipDirs, "tests", "test", "__tests__", "spec", "specs")
	}

	for _, dir := range skipDirs {
		if info.IsDir() && name == dir {
			return true
		}
		if strings.Contains(path, string(filepath.Separator)+dir+string(filepath.Separator)) {
			return true
		}
	}

	if !includeTests && !info.IsDir() && isTestFile(name) {
		return true
	}

	return false
}

func isTestFile(name string) bool {
	testPatterns := []string{
		"_test.go",
		"_test.py", "test_",
		".test.js", ".spec.js", ".test.jsx", ".spec.jsx",
		".test.ts", ".spec.ts", ".test.tsx", ".spec.tsx",
		"Test.java", "Tests.java",
		"Test.cs", "Tests.cs",
		"_spec.rb", "_test.rb",
		"Test.php", "_test.php",
		"Tests.swift", "Test.swift",
		"Test.kt", "Tests.kt",
		"Test.scala", "Spec.scala",
		"_test.c", "_test.cpp", "Test.cpp", "_test.cc", "Test.cc",
		"_test.exs",
		"_test.clj",
		"Spec.hs", "Test.hs",
		"_test.dart",
		"_test.R",
		"_test.jl",
		"_test.lua",
		"_test.rs",
		"_test.m", "_test.mm",
		".test.vue",
		"_test.erl",
	}

	for _, pattern := range testPatterns {
		if strings.HasSuffix(name, pattern) {
			return true
		}
		if strings.HasPrefix(name, "test_") && (strings.HasSuffix(name, ".py") || strings.HasSuffix(name, ".R")) {
			return true
		}
	}

	if strings.HasSuffix(name, ".t") && !strings.Contains(name, ".") {
		return true
	}

	return false
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
			rawJSON, err := json.Marshal(nf)
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

		finding.Type = scan.DeriveFindingType(
			len(nf.NormalizedRemediation.VulnerabilityTypeMetadata.CVEs) > 0,
			loc.HasSecret,
			finding.FindingCategory,
		)

		if loc.HasSecret && finding.CodeSnippet != "" {
			finding.CodeSnippet = util.MaskSecretInLine(finding.CodeSnippet)
		}

		finding.Title = finding.Description

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
