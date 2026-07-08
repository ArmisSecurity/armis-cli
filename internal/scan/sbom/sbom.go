// Package sbom provides SBOM-to-VEX scanning functionality: it uploads a
// pre-existing SBOM artifact and downloads the OpenVEX document the backend
// generates from it (artifact_type=sbom, vex_generate=true).
package sbom

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

// Scanner uploads an SBOM artifact and retrieves the generated OpenVEX document.
type Scanner struct {
	client       *api.Client
	noProgress   bool
	tenantID     string
	timeout      time.Duration
	pollInterval time.Duration
	vexOutput    string // Output path for VEX file (empty = default .armis/<artifact>-vex.json)
}

// NewScanner creates a new SBOM scanner.
func NewScanner(client *api.Client, noProgress bool, tenantID string, timeout time.Duration) *Scanner {
	return &Scanner{
		client:       client,
		noProgress:   noProgress,
		tenantID:     tenantID,
		timeout:      timeout,
		pollInterval: 5 * time.Second,
	}
}

// WithPollInterval sets a custom poll interval (used for testing).
func (s *Scanner) WithPollInterval(d time.Duration) *Scanner {
	s.pollInterval = d
	return s
}

// WithVEXOutput sets a custom output path for the VEX document.
func (s *Scanner) WithVEXOutput(path string) *Scanner {
	s.vexOutput = path
	return s
}

// Scan uploads the SBOM artifact at path and downloads the generated VEX
// document. path may be a single SBOM file (.json/.xml), a directory of SBOMs,
// or an already-built .tar/.tar.gz/.tgz. Returns a ScanResult (with no
// findings — an SBOM scan produces a VEX document, not findings).
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
	var uploadFile *os.File
	var uploadSize int64
	var filename string
	var cleanup func()

	if !info.IsDir() && scan.HasAllowedTarExtension(filepath.Base(absPath)) {
		// Pre-built tarball: validate format and upload directly.
		if err := scan.ValidateTarballFormat(absPath); err != nil {
			return nil, fmt.Errorf("invalid tarball: %w", err)
		}
		if info.Size() > MaxSBOMSize {
			return nil, fmt.Errorf("SBOM tarball size (%d bytes) exceeds maximum allowed size (%d bytes)", info.Size(), MaxSBOMSize)
		}
		// armis:ignore cwe:22 reason:absPath sanitized by util.SanitizePath above; opened read-only for upload
		f, openErr := os.Open(absPath) //nolint:gosec // G304: path sanitized above
		if openErr != nil {
			return nil, fmt.Errorf("failed to open tarball: %w", openErr)
		}
		uploadFile = f
		uploadSize = info.Size()
		filename = filepath.Base(absPath)
		cleanup = func() { _ = f.Close() }
	} else {
		// File or directory: pack into a temp tar.gz, then upload from disk so
		// the HTTP client can set Content-Length (real S3 requires it on POST).
		tmpFile, tmpErr := os.CreateTemp("", "armis-sbom-*.tar.gz")
		if tmpErr != nil {
			return nil, fmt.Errorf("failed to create temp tarball: %w", tmpErr)
		}
		tmpPath := tmpFile.Name()
		cleanup = func() {
			_ = tmpFile.Close()
			_ = os.Remove(tmpPath)
		}

		select {
		case <-ctx.Done():
			cleanup()
			return nil, ctx.Err()
		default:
		}

		if tarErr := tarGzPath(absPath, info, tmpFile); tarErr != nil {
			cleanup()
			return nil, fmt.Errorf("failed to package SBOM: %w", tarErr)
		}
		if err := tmpFile.Sync(); err != nil {
			cleanup()
			return nil, fmt.Errorf("failed to flush tarball: %w", err)
		}
		tarInfo, statErr := tmpFile.Stat()
		if statErr != nil {
			cleanup()
			return nil, fmt.Errorf("failed to stat tarball: %w", statErr)
		}
		if tarInfo.Size() > MaxSBOMSize {
			cleanup()
			return nil, fmt.Errorf("SBOM archive size (%d bytes) exceeds maximum allowed size (%d bytes)", tarInfo.Size(), MaxSBOMSize)
		}
		if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
			cleanup()
			return nil, fmt.Errorf("failed to rewind tarball: %w", err)
		}
		uploadFile = tmpFile
		uploadSize = tarInfo.Size()
		filename = artifactName(absPath) + ".tar.gz"
	}
	defer cleanup()

	spinner.Update("Uploading to Armis Cloud...")

	ingestOpts := api.IngestOptions{
		TenantID:     s.tenantID,
		ArtifactType: "sbom",
		Filename:     filename,
		Data:         uploadFile,
		Size:         uploadSize,
		GenerateVEX:  true, // --vex is implied for `scan sbom`
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

	analysisSpinner := progress.NewSpinnerWithContext(ctx, "Generating VEX from SBOM...", s.noProgress)
	analysisSpinner.Start()
	defer analysisSpinner.Stop()

	_, err = s.client.WaitForIngest(ctx, s.tenantID, scanID, s.pollInterval, s.timeout,
		func(status model.IngestStatusData) {
			analysisSpinner.Update(scan.FormatScanStatus(status.ScanStatus, "Generating VEX from SBOM..."))
		})
	elapsed := analysisSpinner.GetElapsed()
	analysisSpinner.Stop()
	if err != nil {
		return nil, fmt.Errorf("failed to wait for scan: %w", err)
	}

	fmt.Fprintf(os.Stderr, "%s %s\n\n",
		styles.MutedText.Render("Scan completed in"),
		styles.Duration.Render(scan.FormatElapsed(elapsed)))

	// Download the generated VEX document. An SBOM scan produces no normalized
	// findings, so we go straight to the VEX artifact.
	art := artifactName(absPath)
	vexPath := s.resolveVEXPath(art)

	opts := &scan.SBOMVEXOptions{GenerateVEX: true, VEXOutput: s.vexOutput}
	downloader := scan.NewSBOMVEXDownloader(s.client, s.tenantID, opts)
	if err := downloader.Download(ctx, scanID, art); err != nil {
		return nil, fmt.Errorf("failed to download VEX: %w", err)
	}

	// Best-effort statement count for a friendlier summary line. A read failure
	// here is non-fatal: the file is already on disk and the downloader printed
	// its own "VEX saved to" line.
	if n, ok := countVEXStatements(vexPath); ok {
		fmt.Fprintf(os.Stderr, "%s %s\n",
			styles.SuccessText.Render("VEX generated →"),
			styles.Bold.Render(fmt.Sprintf("%s (%d statement%s)", vexPath, n, plural(n))))
	} else {
		fmt.Fprintf(os.Stderr, "%s %s\n",
			styles.SuccessText.Render("VEX generated →"),
			styles.Bold.Render(vexPath))
	}

	// An SBOM scan yields no findings; return an empty completed result so
	// --fail-on / summary / findings-table logic degrades gracefully.
	return &model.ScanResult{
		ScanID:   scanID,
		Status:   "completed",
		Findings: nil,
		Summary: model.Summary{
			BySeverity: make(map[model.Severity]int),
			ByType:     make(map[model.FindingType]int),
			ByCategory: make(map[string]int),
		},
	}, nil
}

// resolveVEXPath mirrors the SBOMVEXDownloader's default-path logic so the
// summary line points at the same file the downloader wrote.
func (s *Scanner) resolveVEXPath(art string) string {
	if s.vexOutput != "" {
		return s.vexOutput
	}
	return filepath.Join(".armis", filepath.Base(art)+"-vex.json")
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
	// armis:ignore cwe:22 reason:path is the CLI-controlled VEX output path (flag or .armis default), already sanitized by SanitizePath in downloadAndSave
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is the sanitized VEX output path
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
