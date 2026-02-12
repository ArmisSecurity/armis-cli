// Package api provides the client for interacting with the Armis security API.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/httpclient"
	"github.com/ArmisSecurity/armis-cli/internal/model"
)

// DownloadTimeout is the default timeout for downloading files from pre-signed URLs.
const DownloadTimeout = 5 * time.Minute

// MaxDownloadSize is the maximum allowed size for downloaded files (100MB).
// This protects against memory exhaustion from maliciously large responses.
const MaxDownloadSize = 100 * 1024 * 1024

// MaxUploadSize is the maximum allowed upload size (5GB).
// This provides defense-in-depth validation at the API layer.
const MaxUploadSize = 5 * 1024 * 1024 * 1024

// MaxAPIResponseSize is the maximum allowed size for API JSON responses (1MB).
// This protects against memory exhaustion from maliciously large API responses.
const MaxAPIResponseSize = 1 * 1024 * 1024

// URL scheme and host constants for security validation.
const (
	schemeHTTPS    = "https"
	hostLocalhost  = "localhost"
	hostLoopbackIP = "127.0.0.1"
)

// AuthHeaderProvider provides authorization headers for API requests.
// This interface allows for different authentication mechanisms (JWT, Basic auth)
// while keeping the API client decoupled from specific auth implementations.
type AuthHeaderProvider interface {
	GetAuthorizationHeader(ctx context.Context) (string, error)
}

// Client is the API client for communicating with the Armis security service.
type Client struct {
	httpClient       *httpclient.Client
	uploadHTTPClient *httpclient.Client
	baseURL          string
	authProvider     AuthHeaderProvider
	debug            bool
	uploadTimeout    time.Duration
	allowLocalURLs   bool
}

// ClientOption is a functional option for configuring the Client.
type ClientOption func(*Client)

// WithHTTPClient sets a custom HTTP client for the API client.
func WithHTTPClient(client *httpclient.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = client
		c.uploadHTTPClient = client
	}
}

// WithAllowLocalURLs enables localhost/127.0.0.1 URLs for presigned URL validation.
// This should only be used in tests. Production code should never enable this option.
func WithAllowLocalURLs(allow bool) ClientOption {
	return func(c *Client) {
		c.allowLocalURLs = allow
	}
}

// NewClient creates a new API client with the given configuration.
// Returns an error if the URL is invalid or uses non-HTTPS for non-localhost hosts.
//
// The authProvider parameter handles authorization for all API requests.
// Use auth.NewAuthProvider() to create a provider that supports both
// JWT authentication and legacy Basic authentication.
func NewClient(baseURL string, authProvider AuthHeaderProvider, debug bool, uploadTimeout time.Duration, opts ...ClientOption) (*Client, error) {
	// Validate URL
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL %q: %w", baseURL, err)
	}

	// Enforce HTTPS for non-localhost hosts to protect credentials
	if parsedURL.Scheme != schemeHTTPS {
		host := parsedURL.Hostname()
		if host != hostLocalhost && host != hostLoopbackIP {
			return nil, fmt.Errorf("HTTPS required for non-localhost URL %q to protect credentials", baseURL)
		}
	}

	if uploadTimeout == 0 {
		uploadTimeout = 10 * time.Minute
	}

	httpClient := httpclient.NewClient(httpclient.Config{
		RetryMax:     3,
		RetryWaitMin: 1 * time.Second,
		RetryWaitMax: 10 * time.Second,
		Timeout:      60 * time.Second,
	})

	uploadHTTPClient := httpclient.NewClient(httpclient.Config{
		RetryMax:       3,
		RetryWaitMin:   1 * time.Second,
		RetryWaitMax:   10 * time.Second,
		DisableTimeout: true,
	})

	client := &Client{
		httpClient:       httpClient,
		uploadHTTPClient: uploadHTTPClient,
		baseURL:          baseURL,
		authProvider:     authProvider,
		debug:            debug,
		uploadTimeout:    uploadTimeout,
	}

	for _, opt := range opts {
		opt(client)
	}

	return client, nil
}

// IsDebug returns whether debug mode is enabled.
func (c *Client) IsDebug() bool {
	return c.debug
}

// setAuthHeader sets the Authorization header on a request, but only if the
// request URL uses HTTPS (or localhost for testing). This prevents credential
// exposure over insecure channels.
//
// For JWT auth: sends raw JWT token (no "Bearer" prefix)
// For Basic auth: sends "Basic <token>" per RFC 7617
//
// NOTE: The backend expects raw JWT tokens without the "Bearer" prefix.
// This is unconventional but matches the backend API contract.
//
// SECURITY NOTE: The localhost/127.0.0.1 exception is intentional for local
// development and testing environments where HTTPS certificates are not available.
// Production deployments must always use HTTPS.
func (c *Client) setAuthHeader(ctx context.Context, req *http.Request) error {
	host := req.URL.Hostname()
	scheme := strings.ToLower(req.URL.Scheme)

	// Require HTTPS for non-localhost hosts to protect credentials
	// #nosec G402 -- Localhost exception intentional for local development/testing
	if host != hostLocalhost && host != hostLoopbackIP && scheme != schemeHTTPS {
		return fmt.Errorf("refusing to send credentials over insecure scheme %q", scheme)
	}

	authHeader, err := c.authProvider.GetAuthorizationHeader(ctx)
	if err != nil {
		return fmt.Errorf("failed to get authorization header: %w", err)
	}
	req.Header.Set("Authorization", authHeader)
	return nil
}

// IngestOptions contains options for the artifact ingestion request.
type IngestOptions struct {
	TenantID     string
	ArtifactType string
	Filename     string
	Data         io.Reader
	Size         int64
	GenerateSBOM bool
	GenerateVEX  bool
}

// StatusCallback is called on each poll with the current scan status.
// It allows callers to react to status changes (e.g., updating a spinner).
type StatusCallback func(status model.IngestStatusData)

// StartIngest uploads an artifact for scanning and returns the scan ID.
func (c *Client) StartIngest(ctx context.Context, opts IngestOptions) (string, error) {
	// Validate upload size for defense-in-depth
	if opts.Size > MaxUploadSize {
		return "", fmt.Errorf("upload size (%d bytes) exceeds maximum allowed (%d bytes)", opts.Size, MaxUploadSize)
	}

	uploadCtx, cancel := context.WithTimeout(ctx, c.uploadTimeout)
	defer cancel()

	start := time.Now()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	if err := writer.WriteField("tenant_id", opts.TenantID); err != nil {
		return "", fmt.Errorf("failed to write tenant_id field: %w", err)
	}

	if err := writer.WriteField("artifact_type", opts.ArtifactType); err != nil {
		return "", fmt.Errorf("failed to write artifact_type field: %w", err)
	}

	if err := writer.WriteField("scan_type", "full"); err != nil {
		return "", fmt.Errorf("failed to write scan_type field: %w", err)
	}

	// Add SBOM/VEX generation flags if requested
	if opts.GenerateSBOM {
		if c.debug {
			fmt.Printf("\n=== DEBUG: Sending sbom_generate=true ===\n")
		}
		if err := writer.WriteField("sbom_generate", "true"); err != nil {
			return "", fmt.Errorf("failed to write sbom_generate field: %w", err)
		}
	}
	if opts.GenerateVEX {
		if c.debug {
			fmt.Printf("\n=== DEBUG: Sending vex_generate=true ===\n")
		}
		if err := writer.WriteField("vex_generate", "true"); err != nil {
			return "", fmt.Errorf("failed to write vex_generate field: %w", err)
		}
	}

	// Use filepath.Base to sanitize filename and prevent path traversal in multipart
	part, err := writer.CreateFormFile("tar_file", filepath.Base(opts.Filename))
	if err != nil {
		return "", fmt.Errorf("failed to create form file: %w", err)
	}

	if _, err := io.Copy(part, opts.Data); err != nil {
		return "", fmt.Errorf("failed to copy file data: %w", err)
	}

	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("failed to close multipart writer: %w", err)
	}

	endpoint := strings.TrimSuffix(c.baseURL, "/") + "/api/v1/ingest/tar"
	req, err := http.NewRequestWithContext(uploadCtx, "POST", endpoint, body)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Use setAuthHeader to ensure credentials are only sent over HTTPS
	if err := c.setAuthHeader(uploadCtx, req); err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := c.uploadHTTPClient.Do(req)
	if err != nil {
		elapsed := time.Since(start).Round(time.Millisecond)
		return "", fmt.Errorf("upload request failed after %s (tar size=%s): %w", elapsed, formatBytes(opts.Size), err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body read-only

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		elapsed := time.Since(start).Round(time.Millisecond)
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("upload failed after %s (tar size=%s, status=%s): %s",
			elapsed, formatBytes(opts.Size), resp.Status, strings.TrimSpace(string(bodyBytes)))
	}

	var result model.IngestUploadResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return result.ScanID, nil
}

// GetIngestStatus retrieves the current status of an ingestion.
func (c *Client) GetIngestStatus(ctx context.Context, tenantID, scanID string) (*model.IngestStatusResponse, error) {
	endpoint := strings.TrimSuffix(c.baseURL, "/") + "/api/v1/ingest/status/"
	params := url.Values{}
	params.Add("tenant_id", tenantID)
	params.Add("scan_id", scanID)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint+"?"+params.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Use setAuthHeader to ensure credentials are only sent over HTTPS
	if err := c.setAuthHeader(ctx, req); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get ingest status: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body read-only

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, MaxAPIResponseSize))
		return nil, fmt.Errorf("get status failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result model.IngestStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// WaitForIngest polls until the ingestion is complete or times out.
// If onStatus is non-nil, it is called on each poll with the current status.
func (c *Client) WaitForIngest(ctx context.Context, tenantID, scanID string, pollInterval time.Duration, timeout time.Duration, onStatus StatusCallback) (*model.IngestStatusData, error) {
	if timeout <= 0 {
		timeout = 60 * time.Minute
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-timeoutCtx.Done():
			if timeoutCtx.Err() == context.DeadlineExceeded {
				return nil, fmt.Errorf("scan timed out after %v (scan ID: %s)", timeout, scanID)
			}
			return nil, timeoutCtx.Err()
		case <-ticker.C:
			statusResp, err := c.GetIngestStatus(timeoutCtx, tenantID, scanID)
			if err != nil {
				return nil, fmt.Errorf("failed to check scan status: %w", err)
			}

			if len(statusResp.Data) == 0 {
				return nil, fmt.Errorf("no status data returned for scan %s", scanID)
			}

			status := statusResp.Data[0]

			if onStatus != nil {
				onStatus(status)
			}

			statusUpper := strings.ToUpper(status.ScanStatus)

			if statusUpper == "COMPLETED" || statusUpper == "FAILED" {
				if status.LastError != nil && *status.LastError != "" {
					return nil, fmt.Errorf("scan failed: %s", *status.LastError)
				}
				return &status, nil
			}
		}
	}
}

// FetchNormalizedResults retrieves a page of normalized scan results.
func (c *Client) FetchNormalizedResults(ctx context.Context, tenantID, scanID string, limit int, cursor string) (*model.NormalizedResultsResponse, error) {
	endpoint := strings.TrimSuffix(c.baseURL, "/") + "/api/v1/ingest/normalized-results"
	params := url.Values{}
	params.Add("tenant_id", tenantID)
	params.Add("scan_id", scanID)
	params.Add("limit", fmt.Sprintf("%d", limit))
	params.Add("include_false_positive", "FALSE")
	if cursor != "" {
		params.Add("cursor", cursor)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint+"?"+params.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Use setAuthHeader to ensure credentials are only sent over HTTPS
	if err := c.setAuthHeader(ctx, req); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch normalized results: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body read-only

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, MaxAPIResponseSize))
		return nil, fmt.Errorf("fetch results failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, MaxAPIResponseSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if c.debug {
		fmt.Printf("\n=== DEBUG: Normalized Results API Response ===\n%s\n=== END DEBUG ===\n\n", string(bodyBytes))
	}

	var result model.NormalizedResultsResponse
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// FetchAllNormalizedResults retrieves all normalized scan results with pagination.
func (c *Client) FetchAllNormalizedResults(ctx context.Context, tenantID, scanID string, pageLimit int) ([]model.NormalizedFinding, error) {
	var allFindings []model.NormalizedFinding
	cursor := ""

	for {
		page, err := c.FetchNormalizedResults(ctx, tenantID, scanID, pageLimit, cursor)
		if err != nil {
			return nil, err
		}

		for _, scanResult := range page.Data.ScanResults {
			allFindings = append(allFindings, scanResult.Findings...)
		}

		if page.Pagination.NextCursor == nil || *page.Pagination.NextCursor == "" {
			break
		}

		cursor = *page.Pagination.NextCursor
	}

	return allFindings, nil
}

// GetScanResult retrieves the result of a completed scan.
func (c *Client) GetScanResult(ctx context.Context, scanID string) (*model.ScanResult, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/scans/"+scanID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Use setAuthHeader to ensure credentials are only sent over HTTPS
	if err := c.setAuthHeader(ctx, req); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get scan result: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body read-only

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, MaxAPIResponseSize))
		return nil, fmt.Errorf("get scan failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result model.ScanResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// WaitForScan polls until the scan is complete.
func (c *Client) WaitForScan(ctx context.Context, scanID string, pollInterval time.Duration) (*model.ScanResult, error) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			result, err := c.GetScanResult(ctx, scanID)
			if err != nil {
				return nil, err
			}

			if result.Status == "completed" || result.Status == "failed" {
				return result, nil
			}
		}
	}
}

func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for n/div >= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// ArtifactScanResultsResponse represents the response from the artifact scan results endpoint.
type ArtifactScanResultsResponse struct {
	ScanStatus      string            `json:"scan_status"`
	Results         map[string]string `json:"results"` // key -> presigned URL (e.g., "sbom_results", "vex_results")
	ScanCompletedAt *string           `json:"scan_completed_at"`
	StatusUpdatedAt *string           `json:"status_updated_at"`
}

// FetchArtifactScanResults retrieves the scan results including pre-signed URLs for SBOM and VEX documents.
func (c *Client) FetchArtifactScanResults(ctx context.Context, tenantID, scanID string) (*ArtifactScanResultsResponse, error) {
	endpoint := strings.TrimSuffix(c.baseURL, "/") + "/api/v1/ingest/results"
	params := url.Values{}
	params.Add("tenant_id", tenantID)
	params.Add("scan_id", scanID)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint+"?"+params.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Use setAuthHeader to ensure credentials are only sent over HTTPS
	if err := c.setAuthHeader(ctx, req); err != nil {
		return nil, fmt.Errorf("failed to set auth header: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch artifact scan results: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body read-only

	if resp.StatusCode == http.StatusNotFound {
		if c.debug {
			fmt.Printf("\n=== DEBUG: FetchArtifactScanResults returned 404 for scan_id=%s ===\n", scanID)
		}
		return nil, nil // Results not yet available
	}

	// Use LimitReader to prevent memory exhaustion from large responses
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, MaxAPIResponseSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if c.debug {
		fmt.Printf("\n=== DEBUG: Artifact Scan Results API Response ===\n%s\n=== END DEBUG ===\n\n", string(bodyBytes))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch results failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}

	var result ArtifactScanResultsResponse
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// ValidatePresignedURL validates that a presigned URL points to a recognized S3 endpoint
// and uses HTTPS to protect authentication signatures embedded in the URL.
// This prevents SSRF attacks by ensuring downloads only go to expected cloud storage hosts.
// Localhost URLs are only allowed if WithAllowLocalURLs(true) was set on the client.
func (c *Client) ValidatePresignedURL(presignedURL string) error {
	parsed, err := url.Parse(presignedURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	host := strings.ToLower(parsed.Hostname())
	scheme := strings.ToLower(parsed.Scheme)

	// Only allow localhost/127.0.0.1 if explicitly enabled (for testing only)
	if host == hostLocalhost || host == hostLoopbackIP {
		if c.allowLocalURLs {
			return nil
		}
		return fmt.Errorf("URL host %q is not a recognized S3 endpoint", host)
	}

	// Require HTTPS for non-localhost URLs to protect presigned URL signatures
	// Presigned URLs contain AWS authentication signatures that must not be exposed
	if scheme != schemeHTTPS {
		return fmt.Errorf("presigned URL must use HTTPS to protect authentication signatures")
	}

	// Allow AWS S3 bucket URL patterns:
	// - bucket.s3.amazonaws.com (legacy)
	// - bucket.s3.region.amazonaws.com (current)
	// - s3.region.amazonaws.com/bucket (path-style)
	if strings.HasSuffix(host, ".amazonaws.com") && strings.Contains(host, "s3") {
		return nil
	}

	return fmt.Errorf("URL host %q is not a recognized S3 endpoint", host)
}

// DownloadFromPresignedURL downloads content from a pre-signed S3 URL.
// The URL is validated to ensure it points to a recognized S3 endpoint and uses HTTPS.
func (c *Client) DownloadFromPresignedURL(ctx context.Context, presignedURL string) ([]byte, error) {
	// Validate URL to prevent SSRF attacks and ensure HTTPS
	if err := c.ValidatePresignedURL(presignedURL); err != nil {
		return nil, fmt.Errorf("invalid presigned URL: %w", err)
	}

	// Add timeout protection for large downloads
	downloadCtx, cancel := context.WithTimeout(ctx, DownloadTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(downloadCtx, "GET", presignedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create download request: %w", err)
	}

	// Note: Pre-signed URLs include authentication, so no auth header needed
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body read-only

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	// Use LimitReader to prevent memory exhaustion from large responses
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxDownloadSize+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read download response: %w", err)
	}

	if int64(len(data)) > MaxDownloadSize {
		return nil, fmt.Errorf("download exceeds maximum allowed size (%d bytes)", MaxDownloadSize)
	}

	return data, nil
}
