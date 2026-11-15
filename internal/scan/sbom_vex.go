// Package scan provides shared scanning utilities.
package scan

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"

	"github.com/ArmisSecurity/armis-cli/internal/api"
	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/util"
)

// Result key constants for SBOM/VEX API responses.
const (
	ResultKeySBOM     = "sbom_results"      // CycloneDX SBOM (default)
	ResultKeySBOMSPDX = "sbom_spdx_results" // SPDX 2.3 SBOM (--sbom-format spdx)
	ResultKeyVEX      = "vex_results"
)

// SBOM format identifiers accepted by --sbom-format. These mirror the
// backend SbomFormat enum (Project-Moose); the values are sent verbatim in
// the ingest request's sbom_format field.
const (
	SBOMFormatCycloneDX = "cyclonedx"
	SBOMFormatSPDX      = "spdx"
)

// SBOMVEXOptions configures SBOM and VEX generation during scans.
type SBOMVEXOptions struct {
	GenerateSBOM bool        // Request SBOM generation
	SBOMFormat   string      // SBOM serialization: "cyclonedx" (default) | "spdx"
	GenerateVEX  bool        // Request VEX generation
	SBOMOutput   string      // Output path for SBOM file (empty = default)
	VEXOutput    string      // Output path for VEX file (empty = default)
	BOM          *BOMOptions // BOM downloads (--bom); nil when not requested
}

// SBOMVEXDownloader handles downloading SBOM and VEX artifacts from pre-signed URLs.
type SBOMVEXDownloader struct {
	client   *api.Client
	tenantID string
	opts     *SBOMVEXOptions
}

// NewSBOMVEXDownloader creates a new downloader instance.
func NewSBOMVEXDownloader(client *api.Client, tenantID string, opts *SBOMVEXOptions) *SBOMVEXDownloader {
	return &SBOMVEXDownloader{
		client:   client,
		tenantID: tenantID,
		opts:     opts,
	}
}

// Download fetches SBOM and/or VEX files from pre-signed URLs.
// API errors (fetch failures) are returned to the caller. Missing results
// (404) are only returned as an error when SBOM/VEX generation was actually
// requested; otherwise this no-ops so callers can still surface scanner-skip
// warnings without spurious "artifact results not available" noise.
// Individual file download errors are logged as warnings but don't fail the overall operation,
// as SBOM/VEX download failures should not fail the overall scan.
// The returned string is the backend's scanner-skip reason (empty if no scanner was skipped),
// so callers can surface it in the final scan summary in addition to the warning printed here.
// With BOM options set, the BOM types that could not be downloaded come back
// as a *BOMDownloadError (every type when the results call fails or 404s);
// unlike SBOM/VEX, a failed BOM download makes the scan exit 2.
func (d *SBOMVEXDownloader) Download(ctx context.Context, scanID, artifactName string) (string, error) {
	var bom *BOMOptions
	if d.opts != nil {
		bom = d.opts.BOM
	}

	// Sanitize artifact name to prevent path traversal
	sanitizedName := filepath.Base(artifactName)
	if sanitizedName == "." || sanitizedName == ".." || sanitizedName == string(filepath.Separator) || sanitizedName == "" {
		err := errors.New("invalid artifact name")
		if bom != nil {
			return "", &BOMDownloadError{Types: bom.Types, Err: err}
		}
		return "", err
	}

	results, err := d.client.FetchArtifactScanResults(ctx, d.tenantID, scanID)
	if err != nil {
		err = fmt.Errorf("failed to fetch artifact results: %w", err)
		if bom != nil {
			return "", &BOMDownloadError{Types: bom.Types, Err: err}
		}
		return "", err
	}

	if results == nil {
		// Results not yet populated (404) is only an error if the caller
		// actually asked for SBOM/VEX/BOM output; otherwise this call exists
		// solely to surface scanner-skip warnings, and staying silent avoids
		// spurious "artifact results not available" noise on every scan.
		if bom != nil {
			return "", &BOMDownloadError{Types: bom.Types, Err: errors.New("artifact results not available")}
		}
		if d.opts != nil && (d.opts.GenerateSBOM || d.opts.GenerateVEX) {
			return "", fmt.Errorf("artifact results not available")
		}
		return "", nil
	}

	if d.client.IsDebug() && results.Error != nil {
		fmt.Fprintf(os.Stderr, "=== DEBUG: artifact scan error=%q ===\n", *results.Error)
	}

	// BOMs download before the scanner-skip return, so a skipped scanner
	// does not hide BOMs that were built.
	var bomErr error
	if bom != nil {
		if failed := d.downloadBOMs(ctx, scanID, results, sanitizedName); len(failed) > 0 {
			bomErr = &BOMDownloadError{Types: failed}
		}
	}

	if msg, skipped := results.SkipMessage(); skipped {
		cli.PrintWarningf("Scanner skipped: %s", msg)
		fmt.Fprintln(os.Stderr)
		return msg, bomErr
	}

	if d.opts == nil {
		return "", nil
	}

	// Handle SBOM download. SPDX and CycloneDX land under distinct result
	// keys (the backend can persist both), so pick the key and the default
	// filename by the requested format.
	if d.opts.GenerateSBOM {
		resultKey := ResultKeySBOM
		defaultName := sanitizedName + "-sbom.json"
		if d.opts.SBOMFormat == SBOMFormatSPDX {
			resultKey = ResultKeySBOMSPDX
			defaultName = sanitizedName + "-sbom.spdx.json"
		}
		sbomURL, ok := results.Results[resultKey]
		if ok && sbomURL != "" {
			outputPath := d.opts.SBOMOutput
			if outputPath == "" {
				outputPath = filepath.Join(".armis", defaultName)
			}
			if err := d.downloadAndSave(ctx, sbomURL, outputPath, "SBOM", d.opts.SBOMOutput == ""); err != nil {
				cli.PrintWarningf("%v", err)
			}
		} else {
			cli.PrintWarning("SBOM was requested but not available in results")
		}
	}

	// Handle VEX download
	if d.opts.GenerateVEX {
		vexURL, ok := results.Results[ResultKeyVEX]
		if ok && vexURL != "" {
			outputPath := d.opts.VEXOutput
			if outputPath == "" {
				outputPath = filepath.Join(".armis", sanitizedName+"-vex.json")
			}
			if err := d.downloadAndSave(ctx, vexURL, outputPath, "VEX", d.opts.VEXOutput == ""); err != nil {
				cli.PrintWarningf("%v", err)
			}
		} else {
			cli.PrintWarning("VEX was requested but not available in results")
		}
	}

	return "", bomErr
}

// downloadBOMs downloads each requested BOM type and returns the types that
// failed. A type the server did not store (a key not offered, too_large, or a
// format left out of bom_summary) only warns. A 403, likely a presigned link
// past its 900 s expiry, refetches the results once and retries that type
// once.
func (d *SBOMVEXDownloader) downloadBOMs(ctx context.Context, scanID string, results *api.ArtifactScanResultsResponse, artifact string) (failed []string) {
	opts := d.opts.BOM
	for _, bomType := range opts.Types {
		label := BOMLabel(bomType)
		format, err := ResolveBOMFormat(bomType, opts.Format)
		if err != nil {
			cli.PrintWarningf("%s: %v", label, err)
			failed = append(failed, bomType)
			continue
		}
		key := BOMResultKey(bomType, format)

		url := results.Results[key]
		if url == "" {
			warnBOMNotOffered(results.BOMSummary, bomType, format)
			continue
		}

		data, err := d.fetchArtifact(ctx, url, label)
		var statusErr *api.DownloadStatusError
		if errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusForbidden {
			url, err = d.refetchBOMURL(ctx, scanID, key, label)
			if err == nil {
				data, err = d.fetchArtifact(ctx, url, label)
			}
		}
		if err != nil {
			cli.PrintWarningf("%v", err)
			failed = append(failed, bomType)
			continue
		}

		if err := d.writeBOM(opts, artifact, bomType, format, data); err != nil {
			cli.PrintWarningf("%v", err)
			failed = append(failed, bomType)
			continue
		}
		if isEmptyBOM(data, format) {
			_, _ = fmt.Fprintln(os.Stderr, emptyBOMMessage(bomType, opts.Target))
		}
	}
	return failed
}

// refetchBOMURL fetches the results again for a fresh presigned link to key.
func (d *SBOMVEXDownloader) refetchBOMURL(ctx context.Context, scanID, key, label string) (string, error) {
	fresh, err := d.client.FetchArtifactScanResults(ctx, d.tenantID, scanID)
	if err != nil {
		return "", fmt.Errorf("failed to download %s: refetching expired link: %w", label, err)
	}
	if fresh == nil || fresh.Results[key] == "" {
		return "", fmt.Errorf("failed to download %s: refetching expired link: no link in results", label)
	}
	return fresh.Results[key], nil
}

// warnBOMNotOffered explains why a requested BOM type has no link. None of
// these is a failure: the server built no such BOM, or does not offer BOMs.
func warnBOMNotOffered(summary *api.BOMSummary, bomType, format string) {
	label := BOMLabel(bomType)
	st, ok := summary.TypeStatus(bomType)
	switch {
	case ok && st.Status == api.BOMStatusTooLarge:
		cli.PrintWarningf("%s was larger than 50 MB and was not stored", label)
	case ok && (st.Status == api.BOMStatusGenerated || st.Status == api.BOMStatusEmpty) &&
		st.Formats != nil && !slices.Contains(st.Formats, format):
		cli.PrintWarningf("%s is not available in %s", label, format)
	default:
		cli.PrintWarningf("%s was requested but not available in results", label)
	}
}

// writeBOM writes one BOM to stdout, or to its file under the --bom-output
// directory (DefaultBOMDir when unset).
func (d *SBOMVEXDownloader) writeBOM(opts *BOMOptions, artifact, bomType, format string, data []byte) error {
	label := BOMLabel(bomType)
	if opts.Output == BOMOutputStdout {
		w := opts.Stdout
		if w == nil {
			w = os.Stdout
		}
		if _, err := w.Write(data); err != nil {
			return fmt.Errorf("failed to write %s to stdout: %w", label, err)
		}
		styles := output.GetStyles()
		_, _ = fmt.Fprintln(os.Stderr, styles.SuccessText.Render(label+" written to stdout"))
		return nil
	}
	dir := opts.Output
	if dir == "" {
		dir = DefaultBOMDir
	}
	return d.saveArtifact(filepath.Join(dir, BOMFileName(artifact, bomType, format)), label, data, opts.Output == "")
}

// downloadAndSave downloads from a URL and saves to a file. The output path
// is checked before the download, so a bad path costs no request.
func (d *SBOMVEXDownloader) downloadAndSave(ctx context.Context, url, outputPath, docType string, defaultDir bool) error {
	if _, err := prepareOutputPath(outputPath, docType, defaultDir); err != nil {
		return err
	}
	data, err := d.fetchArtifact(ctx, url, docType)
	if err != nil {
		return err
	}
	return d.saveArtifact(outputPath, docType, data, defaultDir)
}

// fetchArtifact checks a presigned link and downloads it, within the client's
// timeout and size cap. A non-200 answer wraps *api.DownloadStatusError.
func (d *SBOMVEXDownloader) fetchArtifact(ctx context.Context, url, docType string) ([]byte, error) {
	// armis:ignore cwe:918 reason:ValidatePresignedURL IS the SSRF prevention; enforces HTTPS + allowed S3 hosts
	if err := d.client.ValidatePresignedURL(url); err != nil {
		return nil, fmt.Errorf("invalid %s URL: %w", docType, err)
	}

	// armis:ignore cwe:770 reason:DownloadFromPresignedURL enforces 100MB limit via io.LimitReader and 5min timeout
	data, err := d.client.DownloadFromPresignedURL(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("failed to download %s: %w", docType, err)
	}
	return data, nil
}

// saveArtifact writes a downloaded document, pretty-printed by IndentJSON, to
// outputPath, creating its directory with mode 0750. A path from an output
// flag is the user's own and is written in place with mode 0600, as before, so
// /dev/stdout, a FIFO or a device still work. A path the CLI picked itself
// under .armis (defaultDir) goes through replaceInDefaultDir.
func (d *SBOMVEXDownloader) saveArtifact(outputPath, docType string, data []byte, defaultDir bool) error {
	outputPath, err := prepareOutputPath(outputPath, docType, defaultDir)
	if err != nil {
		return err
	}

	if defaultDir {
		err = replaceInDefaultDir(outputPath, IndentJSON(data))
	} else {
		// Write with secure permissions (owner read/write only)
		err = os.WriteFile(outputPath, IndentJSON(data), 0600)
	}
	if err != nil {
		return fmt.Errorf("failed to write %s to %s: %w", docType, outputPath, err)
	}

	styles := output.GetStyles()
	_, _ = fmt.Fprintf(os.Stderr, "%s %s\n",
		styles.SuccessText.Render(fmt.Sprintf("%s saved to:", docType)),
		styles.Bold.Render(outputPath))
	return nil
}

// prepareOutputPath sanitizes an output path and creates its parent
// directory. For a path the CLI picked itself (defaultDir), the directory is
// .armis, which a scanned repository can commit as a symbolic link or another
// non-directory, so it is checked before MkdirAll could follow it. A path from
// an output flag is trusted, as before.
func prepareOutputPath(outputPath, docType string, defaultDir bool) (string, error) {
	// armis:ignore cwe:22 reason:SanitizePath IS the path traversal prevention; outputPath from user flag then sanitized
	sanitizedPath, err := util.SanitizePath(outputPath)
	if err != nil {
		return "", fmt.Errorf("invalid %s output path: %w", docType, err)
	}

	dir := filepath.Dir(sanitizedPath)
	if defaultDir {
		if _, err := plainDir(dir); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("invalid %s output path: %w", docType, err)
		}
	}

	// Ensure parent directory exists
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return "", fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}
	return sanitizedPath, nil
}

// plainDir returns the Lstat information of dir, or an error unless dir is a
// plain directory. A symbolic link fails, and so does a Windows junction,
// which Lstat reports as irregular.
func plainDir(dir string) (fs.FileInfo, error) {
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a plain directory", dir)
	}
	// Windows Lstat reads the file ID only at the first SameFile; read it now,
	// so a later comparison sees this directory, not what the path names then.
	if !os.SameFile(info, info) {
		return nil, fmt.Errorf("cannot identify %s", dir)
	}
	return info, nil
}

// beforeDefaultDirOpen, when set, runs between the check of the default
// directory and its opening. Tests use it to swap the directory.
var beforeDefaultDirOpen func(dir string)

// replaceInDefaultDir writes data to path, in the directory the CLI picked
// itself. The directory must be a plain directory, and the one os.OpenRoot
// then opens, so a swap between the check and the open is refused. Inside it,
// an existing target must be a regular file. data goes to a new 0600 temp file
// that is renamed over the target, so the target is replaced, never written
// through, and ends with mode 0600.
func replaceInDefaultDir(path string, data []byte) error {
	dir, name := filepath.Dir(path), filepath.Base(path)
	checked, err := plainDir(dir)
	if err != nil {
		return err
	}
	if beforeDefaultDirOpen != nil {
		beforeDefaultDirOpen(dir)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close() //nolint:errcheck // directory handle only
	opened, err := root.Stat(".")
	if err != nil {
		return err
	}
	if !os.SameFile(checked, opened) {
		return fmt.Errorf("%s changed while it was opened", dir)
	}

	if info, err := root.Lstat(name); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	tmp := tempFileName()
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = root.Rename(tmp, name)
	}
	if err != nil {
		_ = root.Remove(tmp)
	}
	return err
}

// tempFileName returns a temp file name of fixed length, so a long target
// name cannot push it past the file system's limit on a name.
func tempFileName() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b) // crypto/rand.Read does not fail
	return ".armis-tmp-" + hex.EncodeToString(b)
}

// IndentJSON pretty-prints a JSON document. The backend serves SBOM/VEX
// artifacts minified; indenting keeps them readable on disk. json.Indent
// preserves key order and number formatting. Input that is not valid JSON is
// returned unchanged.
func IndentJSON(data []byte) []byte {
	var buf bytes.Buffer
	if err := json.Indent(&buf, data, "", "  "); err != nil {
		return data
	}
	buf.WriteByte('\n')
	return buf.Bytes()
}
