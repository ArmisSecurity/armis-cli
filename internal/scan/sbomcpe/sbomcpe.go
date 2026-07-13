// Package sbomcpe drives the CPE→NVD SBOM scan flow (PPSC-1136).
//
// The driver accepts a CycloneDX SBOM file (JSON or XML) or a directory of
// SBOM files, packs them into a tar.gz, and hands the tarball off to the
// backend via the standard artifact ingest path with artifact_type=sbom-cpe.
// The backend routes the tarball to the artifact-scanner service's
// CpeSbomScanner which parses each SBOM, queries NVD, and writes findings
// to the normalized results collection. The driver then polls for scan
// completion, downloads the raw per-CPE JSON dump from S3, and returns the
// same *model.ScanResult shape the other scan commands use so summary /
// findings-table / --fail-on all work.
package sbomcpe

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
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
	// MaxSbomSize caps the on-disk size of any single SBOM (or the sum of
	// all SBOMs in a directory) that we're willing to pack + upload. Real
	// asset-inventory SBOMs are typically <10MB; 100MB is generous headroom
	// while still bounding memory + upload time in the worst case.
	MaxSbomSize = 100 * 1024 * 1024

	// ResultKeySBOMCPE is the results_refs key the backend uses when it
	// uploads the raw CpeSbomScanner JSON dump to S3 (see
	// services/artifact-scanner/artifact_scanner/workflow/persist_results_task.py
	// under PPSC-1136).
	ResultKeySBOMCPE = "sbom_cpe_results"
)

// AllowedExtensions are the SBOM file extensions accepted as raw input.
// A pre-packed .tar / .tar.gz / .tgz is also accepted and forwarded as-is.
var AllowedExtensions = []string{".json", ".xml"}

// prunedDirNames are directory names we skip when walking a directory input:
// they hold VCS/build/dependency artefacts that (a) inflate the tarball past
// MaxSbomSize and (b) may contain thousands of .json files that are
// application manifests, not asset SBOMs.
var prunedDirNames = map[string]struct{}{
	".git":         {},
	".hg":          {},
	".svn":         {},
	"node_modules": {},
	"vendor":       {},
	"__pycache__":  {},
	".venv":        {},
	"venv":         {},
	"dist":         {},
	"build":        {},
	"target":       {},
	".tox":         {},
	".idea":        {},
	".vscode":      {},
}

func isPrunedDir(name string) bool {
	_, ok := prunedDirNames[name]
	return ok
}

// Scanner drives the sbom-cpe scan flow.
type Scanner struct {
	client                *api.Client
	noProgress            bool
	tenantID              string
	pageLimit             int
	timeout               time.Duration
	includeNonExploitable bool
	pollInterval          time.Duration
	fetchRetryInterval    time.Duration

	// downloadRaw controls whether the raw per-CPE JSON dump gets pulled
	// from S3 after scan completion. Default is true (matches the CLI's
	// stated behavior of showing the human-readable output alongside
	// findings). Kept as a knob mainly for tests.
	downloadRaw bool
	rawOutput   string
}

// NewScanner creates a new sbom-cpe scanner.
func NewScanner(
	client *api.Client,
	noProgress bool,
	tenantID string,
	pageLimit int,
	timeout time.Duration,
	includeNonExploitable bool,
) *Scanner {
	return &Scanner{
		client:                client,
		noProgress:            noProgress,
		tenantID:              tenantID,
		pageLimit:             pageLimit,
		timeout:               timeout,
		includeNonExploitable: includeNonExploitable,
		pollInterval:          5 * time.Second,
		fetchRetryInterval:    10 * time.Second,
		downloadRaw:           true,
	}
}

// WithPollInterval overrides the poll interval (for tests).
func (s *Scanner) WithPollInterval(d time.Duration) *Scanner {
	s.pollInterval = d
	return s
}

// WithFetchRetryInterval overrides the retry interval (for tests).
func (s *Scanner) WithFetchRetryInterval(d time.Duration) *Scanner {
	s.fetchRetryInterval = d
	return s
}

// WithRawOutput sets a custom path to write the raw per-CPE JSON dump to.
// If empty, the default is .armis/<artifact>-sbom-cpe.json.
func (s *Scanner) WithRawOutput(path string) *Scanner {
	s.rawOutput = path
	return s
}

// WithoutRawDownload disables the S3 raw-JSON download step (for tests).
func (s *Scanner) WithoutRawDownload() *Scanner {
	s.downloadRaw = false
	return s
}

// Scan runs the sbom-cpe scan for the given input path. The path may be:
//   - a single SBOM file (.json or .xml)
//   - a directory containing SBOM files (recursively walked, non-SBOM files skipped)
//   - a pre-built tar / tar.gz / tgz (uploaded as-is)
//
// Whichever shape is provided, the scanner packs it into a tar.gz on a
// tempfile (unless it's already a tar), uploads it via the standard
// /api/v1/ingest/presigned-url + /api/v1/ingest/scan flow with
// artifact_type=sbom-cpe, polls until the scan completes, retrieves the
// normalized findings, and optionally downloads the raw JSON dump.
func (s *Scanner) Scan(ctx context.Context, inputPath string) (*model.ScanResult, error) {
	// armis:ignore cwe:22 reason:SanitizePath IS the traversal prevention; rejects invalid paths
	sanitized, err := util.SanitizePath(inputPath)
	if err != nil {
		return nil, fmt.Errorf("invalid input path: %w", err)
	}
	inputPath = sanitized

	info, err := os.Stat(inputPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("input path does not exist: %s", inputPath)
		}
		return nil, fmt.Errorf("cannot access input path: %w", err)
	}

	// Prepare a tar.gz on disk. If the user already handed us a tarball,
	// forward it verbatim.
	var (
		tarballPath  string
		artifactName string
		cleanupTar   func()
	)

	if isPrebuiltTarball(inputPath) {
		tarballPath = inputPath
		artifactName = trimTarSuffix(filepath.Base(inputPath))
		cleanupTar = func() {} // nothing to remove; caller owns the file
	} else {
		spinner := progress.NewSpinnerWithContext(ctx, "Packing SBOM(s) into tar.gz...", s.noProgress)
		spinner.Start()

		tmpFile, err := os.CreateTemp("", "armis-sbom-cpe-*.tar.gz")
		if err != nil {
			spinner.Stop()
			return nil, fmt.Errorf("failed to create temp tarball: %w", err)
		}
		tarballPath = tmpFile.Name()
		cleanupTar = func() {
			_ = tmpFile.Close()
			_ = os.Remove(tarballPath)
		}

		var packErr error
		if info.IsDir() {
			packErr = packDir(inputPath, tmpFile)
			artifactName = filepath.Base(inputPath)
		} else {
			if err := validateSbomExtension(inputPath); err != nil {
				cleanupTar()
				spinner.Stop()
				return nil, err
			}
			packErr = packSingleFile(inputPath, tmpFile)
			artifactName = trimSbomExtension(filepath.Base(inputPath))
		}
		spinner.Stop()
		if packErr != nil {
			cleanupTar()
			return nil, fmt.Errorf("failed to pack input: %w", packErr)
		}
		if err := tmpFile.Sync(); err != nil {
			cleanupTar()
			return nil, fmt.Errorf("failed to flush tarball: %w", err)
		}
	}
	defer cleanupTar()

	// Enforce the size cap after packing so directories with hundreds of
	// SBOMs are rejected up-front rather than after a lengthy upload.
	tarInfo, err := os.Stat(tarballPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat tarball: %w", err)
	}
	if tarInfo.Size() > MaxSbomSize {
		return nil, fmt.Errorf(
			"packed tarball size (%d bytes) exceeds maximum %d bytes",
			tarInfo.Size(), MaxSbomSize)
	}

	// armis:ignore cwe:22 reason:tarballPath sanitized above (or a tempfile we own)
	tarFile, err := os.Open(tarballPath) //nolint:gosec // G304: path sanitized above
	if err != nil {
		return nil, fmt.Errorf("failed to open tarball: %w", err)
	}
	defer tarFile.Close() //nolint:errcheck // read-only

	uploadSpinner := progress.NewSpinnerWithContext(ctx, "Uploading SBOM(s) to Armis Cloud...", s.noProgress)
	uploadSpinner.Start()
	defer uploadSpinner.Stop()

	ingestOpts := api.IngestOptions{
		TenantID:     s.tenantID,
		ArtifactType: "sbom-cpe",
		Filename:     artifactName + ".tar.gz",
		Data:         tarFile,
		Size:         tarInfo.Size(),
	}
	scanID, err := s.client.StartIngest(ctx, ingestOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to upload SBOM tarball: %w", err)
	}

	uploadSpinner.Stop()
	styles := output.GetStyles()
	fmt.Fprintf(os.Stderr, "%s %s\n\n",
		styles.MutedText.Render("Scan initiated with ID:"),
		styles.ScanID.Render(scanID))

	scanSpinner := progress.NewSpinnerWithContext(ctx, "Matching CPEs against NVD...", s.noProgress)
	scanSpinner.Start()
	defer scanSpinner.Stop()

	_, err = s.client.WaitForIngest(ctx, s.tenantID, scanID, s.pollInterval, s.timeout,
		func(status model.IngestStatusData) {
			scanSpinner.Update(scan.FormatScanStatus(status.ScanStatus, "Matching CPEs against NVD..."))
		})
	elapsed := scanSpinner.GetElapsed()
	if err != nil {
		return nil, fmt.Errorf("failed to wait for scan: %w", err)
	}
	scanSpinner.Stop()
	fmt.Fprintf(os.Stderr, "%s %s\n\n",
		styles.MutedText.Render("Scan completed in"),
		styles.Duration.Render(scan.FormatElapsed(elapsed)))

	// Fetch normalized findings with a bounded retry loop, matching the
	// pattern established by scan_image / scan_repo.
	fetchSpinner := progress.NewSpinnerWithContext(ctx, "Retrieving findings...", s.noProgress)
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
			fetchSpinner.Update(fmt.Sprintf("Retrieving findings (retry %d/%d)...", attempt, maxFetchRetries-1))
			time.Sleep(s.fetchRetryInterval)
		}
	}
	fetchSpinner.Stop()
	if err != nil {
		cli.PrintWarningf("Failed to retrieve findings: %v", err)
		cli.PrintWarningf("Scan completed successfully. Results are available with scan ID: %s", scanID)
		return nil, &output.ErrResultsIncomplete{ScanID: scanID}
	}

	if s.downloadRaw {
		if err := s.downloadRawResults(ctx, scanID, artifactName); err != nil {
			// Non-fatal — the normalized findings are already retrieved.
			cli.PrintWarningf("%v", err)
		}
	}

	return buildScanResult(scanID, findings, s.client.IsDebug(), s.includeNonExploitable), nil
}

// downloadRawResults pulls the CpeSbomScanner raw JSON dump from S3 and
// writes it to the configured raw-output path (or the default under .armis/).
// The CLI keeps this alongside the normalized findings because the raw dump
// contains per-CPE context and the low_confidence flag that are useful for
// triage but aren't fully exposed via MooseFindings.
func (s *Scanner) downloadRawResults(ctx context.Context, scanID, artifactName string) error {
	results, err := s.client.FetchArtifactScanResults(ctx, s.tenantID, scanID)
	if err != nil {
		return fmt.Errorf("failed to fetch scan result refs: %w", err)
	}
	if results == nil {
		return fmt.Errorf("scan result refs not available")
	}
	rawURL, ok := results.Results[ResultKeySBOMCPE]
	if !ok || rawURL == "" {
		return fmt.Errorf("raw sbom-cpe results not available for scan %s", scanID)
	}

	outputPath := s.rawOutput
	if outputPath == "" {
		outputPath = filepath.Join(".armis", filepath.Base(artifactName)+"-sbom-cpe.json")
	}

	// armis:ignore cwe:22 reason:SanitizePath IS the traversal prevention
	sanitized, err := util.SanitizePath(outputPath)
	if err != nil {
		return fmt.Errorf("invalid --sbom-cpe-output path: %w", err)
	}
	outputPath = sanitized

	dir := filepath.Dir(outputPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("failed to create output directory %s: %w", dir, err)
		}
	}

	// armis:ignore cwe:918 reason:ValidatePresignedURL enforces HTTPS + allowlisted S3 hosts
	if err := s.client.ValidatePresignedURL(rawURL); err != nil {
		return fmt.Errorf("invalid raw-results URL: %w", err)
	}
	// armis:ignore cwe:770 reason:DownloadFromPresignedURL enforces 100MB limit
	data, err := s.client.DownloadFromPresignedURL(ctx, rawURL)
	if err != nil {
		return fmt.Errorf("failed to download raw sbom-cpe results: %w", err)
	}
	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write raw sbom-cpe results to %s: %w", outputPath, err)
	}

	styles := output.GetStyles()
	fmt.Fprintf(os.Stderr, "%s %s\n",
		styles.SuccessText.Render("Raw sbom-cpe results saved to:"),
		styles.Bold.Render(outputPath))
	return nil
}

// ---------------------------------------------------------------------------
// Packing helpers
// ---------------------------------------------------------------------------

// isPrebuiltTarball reports whether inputPath already looks like a tarball
// the backend can accept as-is.
func isPrebuiltTarball(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".tar.gz") ||
		strings.HasSuffix(lower, ".tgz") ||
		strings.HasSuffix(lower, ".tar")
}

func trimTarSuffix(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".tar.gz"):
		return name[:len(name)-len(".tar.gz")]
	case strings.HasSuffix(lower, ".tgz"):
		return name[:len(name)-len(".tgz")]
	case strings.HasSuffix(lower, ".tar"):
		return name[:len(name)-len(".tar")]
	}
	return name
}

func trimSbomExtension(name string) string {
	ext := strings.ToLower(filepath.Ext(name))
	if ext == ".json" || ext == ".xml" {
		return name[:len(name)-len(ext)]
	}
	return name
}

// validateSbomExtension rejects a single file whose extension isn't in
// AllowedExtensions. Directory inputs are walked without extension gating —
// non-SBOM files are silently skipped there.
func validateSbomExtension(path string) error {
	ext := strings.ToLower(filepath.Ext(path))
	for _, allowed := range AllowedExtensions {
		if ext == allowed {
			return nil
		}
	}
	return fmt.Errorf("SBOM file extension %q not allowed; expected one of %v", ext, AllowedExtensions)
}

// PackForTest exposes packSingleFile to _test packages so integration tests
// can produce a valid tar.gz that matches what the driver would upload. Kept
// separate from the private helper so removing this shim doesn't change the
// production surface.
func PackForTest(path string, w io.Writer) error {
	return packSingleFile(path, w)
}

// packSingleFile writes a tar.gz containing exactly one file (the SBOM).
func packSingleFile(path string, w io.Writer) error {
	// armis:ignore cwe:22 reason:path sanitized by caller (Scanner.Scan)
	f, err := os.Open(path) //nolint:gosec // G304: sanitized above
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck // read-only

	info, err := f.Stat()
	if err != nil {
		return err
	}

	gw := gzip.NewWriter(w)
	defer gw.Close() //nolint:errcheck // gz Close error is surfaced by tw.Close chain
	tw := tar.NewWriter(gw)
	defer tw.Close() //nolint:errcheck // tar Close error handled below

	hdr, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	hdr.Name = filepath.Base(path)
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := io.Copy(tw, f); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gw.Close()
}

// packDir walks a directory and writes a tar.gz of every SBOM-shaped file
// (extension in AllowedExtensions). Symlinks are skipped to avoid escaping
// the source tree, matching the safety posture of the repo scanner.
func packDir(root string, w io.Writer) error {
	gw := gzip.NewWriter(w)
	defer gw.Close() //nolint:errcheck
	tw := tar.NewWriter(gw)
	defer tw.Close() //nolint:errcheck

	packedAny := false
	walkErr := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Prune VCS / dependency / build dirs — the extension filter alone
		// would pull thousands of package.json files out of node_modules and
		// blow through the 100MB cap (or, worse, ship application manifests
		// to a scanner that expects asset SBOMs).
		if info.IsDir() {
			if path != root && isPrunedDir(info.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		// Skip symlinks entirely (defense against zip-slip-style escapes).
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		allowed := false
		for _, ok := range AllowedExtensions {
			if ext == ok {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}

		// armis:ignore cwe:22 reason:path from filepath.Walk under caller-sanitized root
		f, err := os.Open(path) //nolint:gosec // G304: root sanitized by Scanner.Scan
		if err != nil {
			return err
		}
		defer f.Close() //nolint:errcheck // read-only

		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		// Tar entries always use forward slashes; filepath.Rel yields
		// backslashes on Windows, which the backend extractor would treat
		// as literal filename characters instead of a directory separator.
		hdr.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := io.Copy(tw, f); err != nil {
			return err
		}
		packedAny = true
		return nil
	})
	if walkErr != nil {
		return walkErr
	}
	if !packedAny {
		return fmt.Errorf("no SBOM files (%v) found under %s", AllowedExtensions, root)
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gw.Close()
}

// ---------------------------------------------------------------------------
// Result plumbing.
//
// convertNormalizedFindings / isEmptyFinding / cleanDescription mirror the
// helpers inside internal/scan/image and internal/scan/repo verbatim. The
// two existing scanner packages already duplicate this pair; keeping the
// pattern here means no cross-package refactor and no risk of drift for
// PPSC-1136. If a future ticket lifts them into internal/scan, all three
// call sites can switch over together.
// ---------------------------------------------------------------------------

func buildScanResult(scanID string, normalizedFindings []model.NormalizedFinding, debug, includeNonExploitable bool) *model.ScanResult {
	findings, filteredCount := convertNormalizedFindings(normalizedFindings, debug, includeNonExploitable)

	summary := model.Summary{
		Total:                  len(findings),
		BySeverity:             make(map[model.Severity]int),
		ByType:                 make(map[model.FindingType]int),
		ByCategory:             make(map[string]int),
		FilteredNonExploitable: filteredCount,
	}
	for _, f := range findings {
		summary.BySeverity[f.Severity]++
		summary.ByType[f.Type]++
		if f.FindingCategory != "" {
			summary.ByCategory[f.FindingCategory]++
		}
	}

	return &model.ScanResult{
		ScanID:   scanID,
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

		if nf.NormalizedTask.ExtraData.Fix != nil {
			finding.Fix = nf.NormalizedTask.ExtraData.Fix
		}
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
		if loc.HasSecret && finding.Fix != nil {
			finding.Fix = scan.MaskFixSecrets(finding.Fix)
		}

		finding.Title = scan.GenerateFindingTitle(&finding)
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

// isRetryableError mirrors the retry criteria used by scan_image / scan_repo:
// treat 5xx API responses and timeouts as transient. Substring matching on
// err.Error() would miss *api.APIError values whose stringified form doesn't
// happen to contain one of the hard-coded markers.
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	var apiErr *api.APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode >= 500
	}
	return errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err)
}
