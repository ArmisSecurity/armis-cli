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
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/api"
	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/model"
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
	// bomWritten lists the BOM types Download wrote, to a file or stdout.
	bomWritten []string
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
		var failed []string
		// A 403 refetch hands back fresher links, for --sbom and --vex too.
		if results, failed, d.bomWritten = d.downloadBOMs(ctx, scanID, results, sanitizedName); len(failed) > 0 {
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
			if err := d.downloadAndSave(ctx, sbomURL, outputPath, "SBOM", filePathMode(d.opts.SBOMOutput)); err != nil {
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
			if err := d.downloadAndSave(ctx, vexURL, outputPath, "VEX", filePathMode(d.opts.VEXOutput)); err != nil {
				cli.PrintWarningf("%v", err)
			}
		} else {
			cli.PrintWarning("VEX was requested but not available in results")
		}
	}

	return "", bomErr
}

// DownloadArtifacts runs the downloads of a finished scan: the SBOM, VEX and
// BOM files opts asks for, and the scanner-skip warning. It returns the skip
// reason and the BOM types that could not be downloaded; any other error only
// warns. Ctrl+C during the BOM downloads returns the context's error, so the
// scan exits as cancelled, not as a failed download.
func DownloadArtifacts(ctx context.Context, client *api.Client, tenantID, scanID, artifactName string, opts *SBOMVEXOptions) (string, []string, error) {
	skipReason, bomFailures, _, err := downloadArtifacts(ctx, client, tenantID, scanID, artifactName, opts)
	return skipReason, bomFailures, err
}

// downloadArtifacts is DownloadArtifacts that also returns the BOM types
// written.
func downloadArtifacts(ctx context.Context, client *api.Client, tenantID, scanID, artifactName string, opts *SBOMVEXOptions) (string, []string, []string, error) {
	d := NewSBOMVEXDownloader(client, tenantID, opts)
	skipReason, err := d.Download(ctx, scanID, artifactName)
	bomFailures, err := SplitBOMError(err)
	if err != nil {
		// Log warning but don't fail the scan
		cli.PrintWarningf("%v", err)
	}
	if len(bomFailures) > 0 && ctx.Err() != nil {
		return "", nil, nil, ctx.Err()
	}
	return skipReason, bomFailures, d.bomWritten, nil
}

// BOMOnlyResult downloads the BOMs of a finished BOM-only scan and returns
// its result: no findings, the BOM types written, and those that could not
// be downloaded.
func BOMOnlyResult(ctx context.Context, client *api.Client, tenantID, scanID, artifactName string, opts *SBOMVEXOptions) (*model.ScanResult, error) {
	skipReason, bomFailures, bomWritten, err := downloadArtifacts(ctx, client, tenantID, scanID, artifactName, opts)
	if err != nil {
		return nil, err
	}
	return &model.ScanResult{
		ScanID:      scanID,
		Status:      "completed",
		Summary:     model.Summary{ScannerSkipReason: skipReason},
		BOMFailures: bomFailures,
		BOMWritten:  bomWritten,
	}, nil
}

// downloadBOMs downloads each requested BOM type and returns the results it
// ended with, the types that failed and the types written. A type the server
// did not store (a key not offered, too_large, or a format left out of
// bom_summary) only warns.
// A 403, likely an expired presigned link, refetches the results once and
// retries that type once; the refetched results then serve the remaining
// types and are returned.
func (d *SBOMVEXDownloader) downloadBOMs(ctx context.Context, scanID string, results *api.ArtifactScanResultsResponse, artifact string) (*api.ArtifactScanResultsResponse, []string, []string) {
	var failed, written []string
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
			warnEarlierBOMFile(opts, artifact, bomType, format)
			continue
		}

		data, err := d.fetchArtifact(ctx, url, label)
		var statusErr *api.DownloadStatusError
		if errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusForbidden {
			var fresh *api.ArtifactScanResultsResponse
			url, fresh, err = d.refetchBOMURL(ctx, scanID, key, label)
			if fresh != nil {
				results = fresh
			}
			if err == nil {
				data, err = d.fetchArtifact(ctx, url, label)
			}
		}
		if err != nil {
			cli.PrintWarningf("%v", err)
			failed = append(failed, bomType)
			continue
		}
		if !json.Valid(data) {
			cli.PrintWarningf("%s is not valid JSON", label)
			failed = append(failed, bomType)
			continue
		}

		if err := d.writeBOM(opts, artifact, bomType, format, data); err != nil {
			cli.PrintWarningf("%v", err)
			failed = append(failed, bomType)
			continue
		}
		written = append(written, bomType)
		if bomIsEmpty(results.BOMSummary, bomType, data, format) {
			_, _ = fmt.Fprintln(os.Stderr, emptyBOMMessage(bomType, opts.Target))
		}
	}
	return results, failed, written
}

// refetchBOMURL fetches the results again for a fresh presigned link to key.
// It returns the refetched results whenever the call answered with them, even
// without a link to key.
func (d *SBOMVEXDownloader) refetchBOMURL(ctx context.Context, scanID, key, label string) (string, *api.ArtifactScanResultsResponse, error) {
	fresh, err := d.client.FetchArtifactScanResults(ctx, d.tenantID, scanID)
	if err != nil {
		return "", nil, fmt.Errorf("failed to download %s: refetching expired link: %w", label, serverTextError{err})
	}
	if fresh == nil || fresh.Results[key] == "" {
		return "", fresh, fmt.Errorf("failed to download %s: refetching expired link: no link in results", label)
	}
	return fresh.Results[key], fresh, nil
}

// serverTextError is an error that can carry a server response body, with C0
// and C1 control characters, such as terminal escapes, stripped from its text.
type serverTextError struct{ err error }

func (e serverTextError) Error() string { return util.StripControl(e.err.Error()) }

func (e serverTextError) Unwrap() error { return e.err }

// warnBOMNotOffered explains why a requested BOM type has no link, from its
// bom_summary status when the summary lists the type. None of these changes
// the exit code: the server built or stored no such BOM, or does not offer
// BOMs.
func warnBOMNotOffered(summary *api.BOMSummary, bomType, format string) {
	label := BOMLabel(bomType)
	st, ok := summary.TypeStatus(bomType)
	switch {
	case ok && st.Status == api.BOMStatusTooLarge:
		cli.PrintWarningf("%s was too large to store", label)
	case ok && st.Status == api.BOMStatusNotSupported:
		cli.PrintWarningf("%s is not supported for this scan", label)
	case ok && st.Status == api.BOMStatusFailed:
		// failed_tools covers the whole scan, not this type, and a type can
		// fail with no tool failed, so the tools are named as scan-wide.
		msg := label + " failed on the server"
		if len(summary.FailedTools) > 0 {
			msg += " (tools that failed in this scan: " + util.StripControl(strings.Join(summary.FailedTools, ", ")) + ")"
		}
		cli.PrintWarning(msg)
	case ok && (st.Status == api.BOMStatusGenerated || st.Status == api.BOMStatusEmpty) &&
		st.Formats != nil && !slices.Contains(st.Formats, format):
		cli.PrintWarningf("%s is not available in %s", label, format)
	default:
		cli.PrintWarningf("%s was requested but not available in results", label)
	}
}

// writeBOM writes one BOM to stdout as fetched, or to its file under the
// --bom-output directory (DefaultBOMDir when unset) pretty-printed by
// indentBOM. The CLI picks the file name in either directory, so the file is
// replaced, never written through.
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
	mode := writeInTypedDir
	if opts.Output == "" {
		mode = writeDefaultDir
	}
	return d.saveArtifact(bomFilePath(opts, artifact, bomType, format), label, indentBOM(data), mode)
}

// bomFilePath is the file of one BOM under the --bom-output directory, or
// DefaultBOMDir when unset.
func bomFilePath(opts *BOMOptions, artifact, bomType, format string) string {
	dir := opts.Output
	if dir == "" {
		dir = DefaultBOMDir
	}
	return filepath.Join(dir, BOMFileName(artifact, bomType, format))
}

// warnEarlierBOMFile warns when a BOM type gets no file this run but its
// file path already holds one, which must then be from an earlier run. The
// file is left in place.
func warnEarlierBOMFile(opts *BOMOptions, artifact, bomType, format string) {
	if opts.Output == BOMOutputStdout {
		return
	}
	path := bomFilePath(opts, artifact, bomType, format)
	// armis:ignore cwe:22 reason:read-only existence check; the path is the --bom-output directory joined with a fixed file name
	if _, err := os.Lstat(path); err == nil {
		cli.PrintWarningf("%s is from an earlier run, not this scan", path)
	}
}

// writeMode says how saveArtifact writes a file, by who chose its path.
type writeMode int

const (
	// writeInPlace writes a file path from an output flag (--sbom-output,
	// --vex-output) as given, so /dev/stdout, a FIFO or a device still work.
	writeInPlace writeMode = iota
	// writeDefaultDir replaces a file the CLI named in DefaultBOMDir, which
	// must be a plain directory.
	writeDefaultDir
	// writeInTypedDir replaces a file the CLI named in a directory from an
	// output flag (--bom-output, bom --output). The directory is used as
	// given, a symbolic link included.
	writeInTypedDir
)

// filePathMode is the write mode of an --sbom-output or --vex-output value:
// a typed file path is written in place, and unset is the default .armis.
func filePathMode(output string) writeMode {
	if output == "" {
		return writeDefaultDir
	}
	return writeInPlace
}

// downloadAndSave downloads from a URL and saves to a file. The output path
// is checked before the download, so a bad path costs no request.
func (d *SBOMVEXDownloader) downloadAndSave(ctx context.Context, url, outputPath, docType string, mode writeMode) error {
	if _, err := prepareOutputPath(outputPath, docType, mode); err != nil {
		return err
	}
	data, err := d.fetchArtifact(ctx, url, docType)
	if err != nil {
		return err
	}
	return d.saveArtifact(outputPath, docType, IndentJSON(data), mode)
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

// saveArtifact writes content to outputPath, creating its directory with
// mode 0750. A file path from an output flag is the user's own and is
// written in place with mode 0600 (writeInPlace), as before, so /dev/stdout,
// a FIFO or a device still work. A file the CLI named goes through
// replaceInDefaultDir under .armis (writeDefaultDir), or replaceInTypedDir in
// a directory from an output flag (writeInTypedDir).
func (d *SBOMVEXDownloader) saveArtifact(outputPath, docType string, content []byte, mode writeMode) error {
	outputPath, err := prepareOutputPath(outputPath, docType, mode)
	if err != nil {
		return err
	}

	switch mode {
	case writeDefaultDir:
		err = replaceInDefaultDir(outputPath, content)
	case writeInTypedDir:
		err = replaceInTypedDir(outputPath, content)
	default:
		// Write with secure permissions (owner read/write only)
		err = os.WriteFile(outputPath, content, 0600)
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
// directory. For a path the CLI picked itself (writeDefaultDir), the directory is
// .armis, which a scanned repository can commit as a symbolic link or another
// non-directory, so it is checked before MkdirAll could follow it. A path from
// an output flag is trusted, as before.
func prepareOutputPath(outputPath, docType string, mode writeMode) (string, error) {
	// armis:ignore cwe:22 reason:SanitizePath IS the path traversal prevention; outputPath from user flag then sanitized
	sanitizedPath, err := util.SanitizePath(outputPath)
	if err != nil {
		return "", fmt.Errorf("invalid %s output path: %w", docType, err)
	}

	dir := filepath.Dir(sanitizedPath)
	if mode == writeDefaultDir {
		if err := checkDefaultDir(dir, docType); err != nil {
			return "", err
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

// CheckDefaultOutputDir returns the error the write of a docType file would
// give later when DefaultBOMDir is not a plain directory, such as a symlink
// committed in the scanned repository, so a scan can stop before upload. A
// missing directory passes.
func CheckDefaultOutputDir(docType string) error {
	return checkDefaultDir(DefaultBOMDir, docType)
}

// checkDefaultDir refuses the default output directory dir unless it is a
// plain directory or does not exist yet.
func checkDefaultDir(dir, docType string) error {
	if _, err := plainDir(dir); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("invalid %s output path: %w", docType, err)
	}
	return nil
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
// then opens, so a swap between the check and the open is refused. The file
// is then written by replaceInRoot.
func replaceInDefaultDir(path string, data []byte) error {
	dir := filepath.Dir(path)
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
	return replaceInRoot(root, path, data)
}

// replaceInTypedDir writes data to path, a file name the CLI picked in a
// directory from an output flag. The directory is the user's own and is
// opened as given, through a symbolic link too; the file in it is written by
// replaceInRoot, since a scanned repository can commit a link at that name.
func replaceInTypedDir(path string, data []byte) error {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close() //nolint:errcheck // directory handle only
	return replaceInRoot(root, path, data)
}

// replaceInRoot writes data to the file of path in root. An existing target
// must be a regular file. data goes to a new 0600 temp file that is renamed
// over the target, so the target is replaced, never written through, and
// ends with mode 0600.
func replaceInRoot(root *os.Root, path string, data []byte) error {
	name := filepath.Base(path)
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
