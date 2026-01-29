// Package scan provides shared scanning utilities.
package scan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ArmisSecurity/armis-cli/internal/api"
	"github.com/ArmisSecurity/armis-cli/internal/util"
)

// Result key constants for SBOM/VEX API responses.
const (
	ResultKeySBOM = "sbom_results"
	ResultKeyVEX  = "vex_results"
)

// SBOMVEXOptions configures SBOM and VEX generation during scans.
type SBOMVEXOptions struct {
	GenerateSBOM bool   // Request SBOM generation
	GenerateVEX  bool   // Request VEX generation
	SBOMOutput   string // Output path for SBOM file (empty = default)
	VEXOutput    string // Output path for VEX file (empty = default)
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
// API errors (fetch failures, missing results) are returned to the caller.
// Individual file download errors are logged as warnings but don't fail the overall operation,
// as SBOM/VEX download failures should not fail the overall scan.
func (d *SBOMVEXDownloader) Download(ctx context.Context, scanID, artifactName string) error {
	// Sanitize artifact name to prevent path traversal
	sanitizedName := filepath.Base(artifactName)
	if sanitizedName == "." || sanitizedName == "/" || sanitizedName == "" {
		return fmt.Errorf("invalid artifact name")
	}

	results, err := d.client.FetchArtifactScanResults(ctx, d.tenantID, scanID)
	if err != nil {
		return fmt.Errorf("failed to fetch artifact results: %w", err)
	}

	if results == nil {
		return fmt.Errorf("artifact results not available")
	}

	// Handle SBOM download
	if d.opts.GenerateSBOM {
		sbomURL, ok := results.Results[ResultKeySBOM]
		if ok && sbomURL != "" {
			outputPath := d.opts.SBOMOutput
			if outputPath == "" {
				outputPath = filepath.Join(".armis", sanitizedName+"-sbom.json")
			}
			if err := d.downloadAndSave(ctx, sbomURL, outputPath, "SBOM"); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
			}
		} else {
			fmt.Fprintf(os.Stderr, "Warning: SBOM was requested but not available in results\n")
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
			if err := d.downloadAndSave(ctx, vexURL, outputPath, "VEX"); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
			}
		} else {
			fmt.Fprintf(os.Stderr, "Warning: VEX was requested but not available in results\n")
		}
	}

	return nil
}

// downloadAndSave downloads from a URL and saves to a file.
func (d *SBOMVEXDownloader) downloadAndSave(ctx context.Context, url, outputPath, docType string) error {
	// Validate output path to prevent path traversal attacks
	sanitizedPath, err := util.SanitizePath(outputPath)
	if err != nil {
		return fmt.Errorf("invalid %s output path: %w", docType, err)
	}
	outputPath = sanitizedPath

	// Ensure parent directory exists
	dir := filepath.Dir(outputPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Validate URL to prevent SSRF - only allow recognized S3 endpoints over HTTPS
	if err := d.client.ValidatePresignedURL(url); err != nil {
		return fmt.Errorf("invalid %s URL: %w", docType, err)
	}

	// DownloadFromPresignedURL enforces size limits (100MB max via io.LimitReader)
	// and timeout (5min) to prevent resource exhaustion attacks
	data, err := d.client.DownloadFromPresignedURL(ctx, url)
	if err != nil {
		return fmt.Errorf("failed to download %s: %w", docType, err)
	}

	// Write with secure permissions (owner read/write only)
	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write %s to %s: %w", docType, outputPath, err)
	}

	fmt.Fprintf(os.Stderr, "%s saved to: %s\n", docType, outputPath)
	return nil
}
