// Package sbom provides the unified SBOM scanning driver for the CLI.
//
// A single `armis-cli scan sbom <path>` command handles both CycloneDX
// shapes:
//
//   - Purl-based SBOMs (npm/NuGet/Kobra) → backend routes to Trivy → Grype
//     for optional VEX.
//   - CPE-based SBOMs (Torizon-style asset inventories) → backend routes to
//     the CPE→NVD scanner and (if --vex-output requested) the CPE VEX
//     generator.
//
// The CLI itself is oblivious to the routing: it always sends
// artifact_type=sbom, waits for the scan to complete, downloads the
// normalized findings, and pulls the raw JSON dump from whichever
// results_refs key the backend advertised.
package sbom

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

// MaxSBOMSize is the maximum allowed size for the SBOM upload body. SBOMs are
// small relative to repos/images, but we keep a generous cap so multi-project
// bundles still fit.
const MaxSBOMSize = 512 * 1024 * 1024

// ResultKeySBOMCPE is the results_refs key the backend uses when the sbom
// upload routed to the CPE→NVD path. Locked here (and cross-checked in a
// test) so a rename on either side breaks CI loudly.
const ResultKeySBOMCPE = "sbom_cpe_results"

// Scanner uploads an SBOM artifact and reports findings (plus, optionally, a
// VEX document).
type Scanner struct {
	client                *api.Client
	noProgress            bool
	tenantID              string
	pageLimit             int
	timeout               time.Duration
	includeNonExploitable bool
	pollInterval          time.Duration
	fetchRetryInterval    time.Duration
	rawOutput             string // Raw findings JSON path (empty = default under .armis/)
	vexOutput             string // VEX path; empty ⇒ VEX not requested
	generateVEX           bool
}

// NewScanner creates a new SBOM scanner.
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
		fetchRetryInterval:    2 * time.Second,
	}
}

// WithPollInterval sets a custom poll interval (used for testing).
func (s *Scanner) WithPollInterval(d time.Duration) *Scanner {
	s.pollInterval = d
	return s
}

// WithFetchRetryInterval overrides the delay between /normalized-results
// retries (used for testing).
func (s *Scanner) WithFetchRetryInterval(d time.Duration) *Scanner {
	s.fetchRetryInterval = d
	return s
}

// WithRawOutput sets a custom output path for the raw findings JSON.
func (s *Scanner) WithRawOutput(path string) *Scanner {
	s.rawOutput = path
	return s
}

// WithVEXOutput opts into VEX generation and sets the VEX output path.
// An empty path with generateVEX=true uses the default under .armis/.
func (s *Scanner) WithVEXOutput(path string) *Scanner {
	s.vexOutput = path
	s.generateVEX = true
	return s
}

// Scan uploads the SBOM at path, waits for the backend scan to complete,
// downloads normalized findings, and (if requested) the VEX document.
//
// path may be a single SBOM file (.json/.xml), a directory of SBOMs, or an
// already-built .tar/.tar.gz/.tgz.
func (s *Scanner) Scan(ctx context.Context, path string) (*model.ScanResult, error) {
	// armis:ignore cwe:22 reason:SanitizePath IS the path traversal prevention; rejects invalid paths before use
	sanitizedPath, err := util.SanitizePath(path)
	if err != nil {
		return nil, fmt.Errorf("invalid SBOM path: %w", err)
	}
	path = sanitizedPath

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path: %w", err)
	}

	// armis:ignore cwe:22 reason:absPath resolved from sanitized CLI arg; read-only stat
	info, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat path: %w", err)
	}

	spinner := progress.NewSpinnerWithContext(ctx, "Preparing SBOM for upload...", s.noProgress)
	spinner.Start()
	defer spinner.Stop()

	// Determine the upload body. A pre-built tarball is uploaded as-is; a file
	// or directory is packed into a tar.gz the backend walks for SBOMs.
	uploadFile, uploadSize, filename, cleanup, err := s.prepareUpload(ctx, absPath, info)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	spinner.Update("Uploading to Armis Cloud...")

	ingestOpts := api.IngestOptions{
		TenantID:     s.tenantID,
		ArtifactType: "sbom",
		Filename:     filename,
		Data:         uploadFile,
		Size:         uploadSize,
		GenerateVEX:  s.generateVEX,
	}

	scanID, err := s.client.StartIngest(ctx, ingestOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to upload SBOM: %w", err)
	}

	spinner.Stop()
	styles := output.GetStyles()
	fmt.Fprintf(os.Stderr, "%s %s\n\n",
		styles.MutedText.Render("Scan initiated with ID:"),
		styles.ScanID.Render(scanID))

	analysisSpinner := progress.NewSpinnerWithContext(ctx, "Analyzing SBOM...", s.noProgress)
	analysisSpinner.Start()
	defer analysisSpinner.Stop()

	_, err = s.client.WaitForIngest(ctx, s.tenantID, scanID, s.pollInterval, s.timeout,
		func(status model.IngestStatusData) {
			analysisSpinner.Update(scan.FormatScanStatus(status.ScanStatus, "Analyzing SBOM..."))
		})
	elapsed := analysisSpinner.GetElapsed()
	analysisSpinner.Stop()
	if err != nil {
		return nil, fmt.Errorf("failed to wait for scan: %w", err)
	}

	fmt.Fprintf(os.Stderr, "%s %s\n\n",
		styles.MutedText.Render("Scan completed in"),
		styles.Duration.Render(scan.FormatElapsed(elapsed)))

	// Fetch normalized findings with a bounded retry loop, matching the pattern
	// established by scan_image / scan_repo. Both CPE and purl paths produce
	// findings; the CLI is agnostic to which scanner ran.
	art := artifactName(absPath)
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
			select {
			case <-ctx.Done():
				fetchSpinner.Stop()
				return nil, ctx.Err()
			case <-time.After(s.fetchRetryInterval):
			}
		}
	}
	fetchSpinner.Stop()
	if err != nil {
		cli.PrintWarningf("Failed to retrieve findings: %v", err)
		cli.PrintWarningf("Scan completed successfully. Results are available with scan ID: %s", scanID)
		return nil, &output.ErrResultsIncomplete{ScanID: scanID}
	}

	// Pull the results_refs blob so we can find both the raw findings JSON and
	// (optionally) the VEX doc. The backend advertises either sbom_results
	// (purl path) or sbom_cpe_results (CPE path); we grab whichever is set.
	results, refsErr := s.client.FetchArtifactScanResults(ctx, s.tenantID, scanID)
	if refsErr != nil {
		cli.PrintWarningf("failed to fetch scan result refs: %v", refsErr)
	}

	if results != nil {
		if err := s.downloadRawFindings(ctx, results, art); err != nil {
			// Non-fatal — the normalized findings are already retrieved.
			cli.PrintWarningf("%v", err)
		}
		if s.generateVEX {
			if err := s.downloadVEX(ctx, results, art); err != nil {
				cli.PrintWarningf("%v", err)
			}
		}
	}

	return scan.BuildScanResult(scanID, findings, s.client.IsDebug(), s.includeNonExploitable), nil
}

// downloadRawFindings pulls the raw-findings JSON dump the backend wrote for
// this scan. The results_refs key differs between paths — sbom_cpe_results on
// the CPE path, sbom_results on the purl path — but the shape (per-CVE JSON
// blob) is close enough that the CLI treats it uniformly.
func (s *Scanner) downloadRawFindings(ctx context.Context, results *api.ArtifactScanResultsResponse, art string) error {
	rawURL, source, ok := s.pickRawFindingsURL(results)
	if !ok {
		return fmt.Errorf("raw findings blob not available for this scan")
	}

	outputPath := s.rawOutput
	if outputPath == "" {
		outputPath = filepath.Join(".armis", filepath.Base(art)+"-sbom.json")
	}

	// armis:ignore cwe:22 reason:SanitizePath IS the traversal prevention
	sanitized, err := util.SanitizePath(outputPath)
	if err != nil {
		return fmt.Errorf("invalid --sbom-output path: %w", err)
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
		return fmt.Errorf("failed to download raw findings (%s): %w", source, err)
	}
	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write raw findings to %s: %w", outputPath, err)
	}

	styles := output.GetStyles()
	fmt.Fprintf(os.Stderr, "%s %s\n",
		styles.SuccessText.Render(fmt.Sprintf("Raw findings (%s) saved to:", source)),
		styles.Bold.Render(outputPath))
	return nil
}

// pickRawFindingsURL prefers the CPE-path raw blob when both are present
// (which shouldn't happen — only one scanner runs — but the precedence keeps
// the CPE tag visible in the "Raw findings (cpe)" message when it does).
func (s *Scanner) pickRawFindingsURL(results *api.ArtifactScanResultsResponse) (string, string, bool) {
	if u, present := results.Results[ResultKeySBOMCPE]; present && u != "" {
		return u, "cpe", true
	}
	if u, present := results.Results[scan.ResultKeySBOM]; present && u != "" {
		return u, "purl", true
	}
	return "", "", false
}

// downloadVEX pulls the VEX doc from the vex_results slot. Same key
// regardless of which VEX generator produced it (Grype for purl path,
// CpeVexGenerator for CPE path).
func (s *Scanner) downloadVEX(ctx context.Context, results *api.ArtifactScanResultsResponse, art string) error {
	vexURL, ok := results.Results[scan.ResultKeyVEX]
	if !ok || vexURL == "" {
		return fmt.Errorf("VEX was requested but not available in results (backend may not have generated one)")
	}

	outputPath := s.vexOutput
	if outputPath == "" {
		outputPath = filepath.Join(".armis", filepath.Base(art)+"-vex.json")
	}

	// armis:ignore cwe:22 reason:SanitizePath IS the traversal prevention
	sanitized, err := util.SanitizePath(outputPath)
	if err != nil {
		return fmt.Errorf("invalid --vex-output path: %w", err)
	}
	outputPath = sanitized

	dir := filepath.Dir(outputPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("failed to create VEX output directory %s: %w", dir, err)
		}
	}

	// armis:ignore cwe:918 reason:ValidatePresignedURL enforces HTTPS + allowlisted S3 hosts
	if err := s.client.ValidatePresignedURL(vexURL); err != nil {
		return fmt.Errorf("invalid VEX URL: %w", err)
	}
	// armis:ignore cwe:770 reason:DownloadFromPresignedURL enforces 100MB limit
	data, err := s.client.DownloadFromPresignedURL(ctx, vexURL)
	if err != nil {
		return fmt.Errorf("failed to download VEX: %w", err)
	}
	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write VEX to %s: %w", outputPath, err)
	}

	styles := output.GetStyles()
	if n, ok := countVEXStatements(outputPath); ok {
		fmt.Fprintf(os.Stderr, "%s %s\n",
			styles.SuccessText.Render("VEX generated →"),
			styles.Bold.Render(fmt.Sprintf("%s (%d statement%s)", outputPath, n, plural(n))))
	} else {
		fmt.Fprintf(os.Stderr, "%s %s\n",
			styles.SuccessText.Render("VEX generated →"),
			styles.Bold.Render(outputPath))
	}
	return nil
}

// prepareUpload determines the upload body: either forward a pre-built
// tarball verbatim or pack the file/dir into a temp tar.gz.
func (s *Scanner) prepareUpload(
	ctx context.Context, absPath string, info os.FileInfo,
) (uploadFile *os.File, uploadSize int64, filename string, cleanup func(), err error) {
	if !info.IsDir() && scan.HasAllowedTarExtension(filepath.Base(absPath)) {
		// Pre-built tarball: validate format and upload directly.
		if err := scan.ValidateTarballFormat(absPath); err != nil {
			return nil, 0, "", nil, fmt.Errorf("invalid tarball: %w", err)
		}
		if info.Size() > MaxSBOMSize {
			return nil, 0, "", nil, fmt.Errorf("SBOM tarball size (%d bytes) exceeds maximum allowed size (%d bytes)", info.Size(), MaxSBOMSize)
		}
		// armis:ignore cwe:22 reason:absPath sanitized by util.SanitizePath above; opened read-only for upload
		f, openErr := os.Open(absPath) //nolint:gosec // G304: path sanitized above
		if openErr != nil {
			return nil, 0, "", nil, fmt.Errorf("failed to open tarball: %w", openErr)
		}
		return f, info.Size(), filepath.Base(absPath), func() { _ = f.Close() }, nil
	}

	tmpFile, tmpErr := os.CreateTemp("", "armis-sbom-*.tar.gz")
	if tmpErr != nil {
		return nil, 0, "", nil, fmt.Errorf("failed to create temp tarball: %w", tmpErr)
	}
	tmpPath := tmpFile.Name()
	cleanup = func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
	}

	select {
	case <-ctx.Done():
		cleanup()
		return nil, 0, "", nil, ctx.Err()
	default:
	}

	if tarErr := tarGzPath(absPath, info, tmpFile); tarErr != nil {
		cleanup()
		return nil, 0, "", nil, fmt.Errorf("failed to package SBOM: %w", tarErr)
	}
	if err := tmpFile.Sync(); err != nil {
		cleanup()
		return nil, 0, "", nil, fmt.Errorf("failed to flush tarball: %w", err)
	}
	tarInfo, statErr := tmpFile.Stat()
	if statErr != nil {
		cleanup()
		return nil, 0, "", nil, fmt.Errorf("failed to stat tarball: %w", statErr)
	}
	if tarInfo.Size() > MaxSBOMSize {
		cleanup()
		return nil, 0, "", nil, fmt.Errorf("SBOM archive size (%d bytes) exceeds maximum allowed size (%d bytes)", tarInfo.Size(), MaxSBOMSize)
	}
	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		cleanup()
		return nil, 0, "", nil, fmt.Errorf("failed to rewind tarball: %w", err)
	}
	return tmpFile, tarInfo.Size(), artifactName(absPath) + ".tar.gz", cleanup, nil
}

// artifactName derives a friendly artifact name from a path, stripping tar and
// SBOM extensions so "sbom.json" / "image.tar.gz" both yield a clean stem.
func artifactName(path string) string {
	base := filepath.Base(path)
	for _, ext := range []string{".tar.gz", ".tgz", ".tar"} {
		if strings.HasSuffix(strings.ToLower(base), ext) {
			return base[:len(base)-len(ext)]
		}
	}
	return strings.TrimSuffix(base, filepath.Ext(base))
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// openVEXDoc is the minimal shape we parse to count statements. We only read
// the statements array; the full document is written to disk verbatim.
type openVEXDoc struct {
	Statements []json.RawMessage `json:"statements"`
}

// countVEXStatements reads the VEX file and returns the number of statements.
// ok is false if the file cannot be read or parsed.
func countVEXStatements(path string) (int, bool) {
	// armis:ignore cwe:22 reason:path is the CLI-controlled VEX output path (flag or .armis default), already sanitized by SanitizePath
	data, err := os.ReadFile(path) //nolint:gosec // G304: sanitized VEX output path
	if err != nil {
		return 0, false
	}
	var doc openVEXDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return 0, false
	}
	return len(doc.Statements), true
}

// tarGzPath packs a single file or a directory tree at absPath into a gzip'd
// tar written to w. Symlinks are skipped for safety (mirrors the repo scanner).
func tarGzPath(absPath string, info os.FileInfo, w io.Writer) (err error) {
	gzWriter := gzip.NewWriter(w)
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

	if !info.IsDir() {
		return writeTarFile(tarWriter, absPath, info, filepath.Base(absPath))
	}

	return filepath.Walk(absPath, func(path string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relPath, relErr := filepath.Rel(absPath, path)
		if relErr != nil {
			return relErr
		}
		if relPath == "." {
			return nil
		}
		// Skip symlinks to avoid escaping the input directory.
		if fi.Mode()&os.ModeSymlink != 0 {
			cli.PrintWarningf("skipping symlink %s", relPath)
			if fi.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if fi.IsDir() {
			header, hErr := tar.FileInfoHeader(fi, "")
			if hErr != nil {
				return hErr
			}
			header.Name = filepath.ToSlash(relPath)
			return tarWriter.WriteHeader(header)
		}
		return writeTarFile(tarWriter, path, fi, filepath.ToSlash(relPath))
	})
}

// writeTarFile writes a single regular file into the tar writer under tarName.
func writeTarFile(tarWriter *tar.Writer, path string, info os.FileInfo, tarName string) error {
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	header.Name = tarName
	if err := tarWriter.WriteHeader(header); err != nil {
		return err
	}
	// armis:ignore cwe:22 reason:path is yielded by filepath.Walk within the sanitized input dir, or the single sanitized file; symlinks skipped above
	file, err := os.Open(path) //nolint:gosec // G304: path within sanitized input; symlinks skipped
	if err != nil {
		return err
	}
	// armis:ignore cwe:253 reason:Close error on read-only file is non-actionable; io.Copy catches read failures
	defer file.Close() //nolint:errcheck
	_, err = io.Copy(tarWriter, file)
	return err
}

// isRetryableError mirrors the retry criteria used by the other scan drivers:
// 5xx API responses and timeouts are transient; 4xx and plain errors aren't.
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

