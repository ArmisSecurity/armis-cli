// Package api provides the client for interacting with the Armis security API.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/httpclient"
	"github.com/ArmisSecurity/armis-cli/internal/model"
)

// APIError represents an HTTP API error with a status code, allowing callers
// to distinguish retryable (5xx, timeout) from permanent (4xx) errors.
type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("API error (status %d): %s", e.StatusCode, e.Body)
}

// DownloadTimeout is the default timeout for downloading files from pre-signed URLs.
const DownloadTimeout = 5 * time.Minute

// MaxDownloadSize is the maximum allowed size for downloaded files (100MB).
// This protects against memory exhaustion from maliciously large responses.
const MaxDownloadSize = 100 * 1024 * 1024

// MaxUploadSize is the maximum allowed upload size (5GB).
// This provides defense-in-depth validation at the API layer.
const MaxUploadSize = 5 * 1024 * 1024 * 1024

// MaxAPIResponseSize is the maximum allowed size for API JSON responses (50MB).
// This protects against memory exhaustion from maliciously large API responses
// while allowing legitimate large scan results (which can have many findings).
const MaxAPIResponseSize = 50 * 1024 * 1024

// URL scheme and host constants for security validation.
const (
	schemeHTTPS   = "https"
	schemeHTTP    = "http"
	hostLocalhost = "localhost"
)

// isLoopbackHost reports whether host names the local machine. Accepts
// "localhost" as a special case and otherwise defers to net.ParseIP so any
// loopback representation is caught — 127.0.0.1, ::1, IPv4-mapped forms
// like 0:0:0:0:0:0:0:1, anything in 127.0.0.0/8, etc. A plain string compare
// against "127.0.0.1"/"::1" would miss the expanded IPv6 forms.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, hostLocalhost) {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// copyChunkSize is the buffer size for context-aware copying.
// 256KB reduces syscall overhead for multi-GB uploads while still providing
// sub-second cancellation responsiveness at typical network speeds.
const copyChunkSize = 256 * 1024

// errInvalidWrite indicates a Write returned an impossible byte count.
// This matches Go's internal io package error for invalid writes.
var errInvalidWrite = errors.New("invalid write result")

// maxZeroReads is the maximum consecutive zero-byte reads before returning an error.
// This prevents infinite loops from malformed readers that return (0, nil).
const maxZeroReads = 100

// copyWithContext copies from src to dst while periodically checking context cancellation.
// This allows long-running copies (e.g., multi-GB uploads) to be cancelled promptly.
// Returns the number of bytes copied and any error encountered.
func copyWithContext(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, copyChunkSize)
	var written int64
	var zeroReads int

	for {
		// Check context before each chunk read
		select {
		case <-ctx.Done():
			return written, ctx.Err()
		default:
		}

		nr, rerr := src.Read(buf)
		if nr > 0 {
			zeroReads = 0 // Reset counter on successful read
			nw, werr := dst.Write(buf[:nr])
			// Check for invalid write (negative or wrote more than buffer size)
			// This matches Go's io.Copy implementation pattern
			if nw < 0 || nw > nr {
				nw = 0
				if werr == nil {
					werr = errInvalidWrite
				}
			}
			written += int64(nw)
			if werr != nil {
				return written, werr
			}
			// Check for short write (wrote less than read)
			if nw < nr {
				return written, io.ErrShortWrite
			}
		} else if rerr == nil {
			// Read returned 0 bytes with no error - protect against infinite loop
			zeroReads++
			if zeroReads >= maxZeroReads {
				return written, errors.New("reader returned zero bytes repeatedly without error or EOF")
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return written, nil
			}
			return written, rerr
		}
	}
}

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
	localS3Hosts     []string // exact host:port allowlist for mock S3 (dev only)
}

// ClientOption is a functional option for configuring the Client.
type ClientOption func(*Client)

// WithHTTPClient sets a custom HTTP client for the API client.
// Note: This does NOT override uploadHTTPClient, which has special no-retry
// configuration for streaming uploads. Use WithUploadHTTPClient for that.
func WithHTTPClient(client *httpclient.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = client
	}
}

// WithUploadHTTPClient sets a custom HTTP client for upload operations.
// This is primarily for testing. In production, the default upload client
// is configured with DisableRetry: true because streaming bodies cannot be rewound.
func WithUploadHTTPClient(client *httpclient.Client) ClientOption {
	return func(c *Client) {
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

// WithLocalS3Hosts adds host:port entries to the allowlist for bypassing HTTPS
// and amazonaws.com validation in ValidatePresignedURL. This enables HTTP access
// to mock S3 services during local development (e.g., "awsmock-dev:4566").
//
// Security considerations:
//   - Only use for local development with mock S3 services
//   - Hosts are normalized (trimmed, lowercased) for consistent matching
//   - Matching uses exact string comparison including port numbers
//   - Empty strings are silently ignored
//
// This option should ONLY be set when the CLI is running against localhost or
// private network IPs. See clientOptionsForBaseURL in cmd/root.go for the
// environment detection logic that controls when this option is used.
//
// Example usage:
//
//	client := api.NewClient(baseURL, auth, debug, timeout,
//	    api.WithLocalS3Hosts("awsmock-dev:4566", "localstack:4566"))
func WithLocalS3Hosts(hosts ...string) ClientOption {
	return func(c *Client) {
		for _, h := range hosts {
			// Normalize host entries: trim whitespace and convert to lowercase
			// for consistent case-insensitive matching in ValidatePresignedURL
			if h = strings.TrimSpace(strings.ToLower(h)); h != "" {
				c.localS3Hosts = append(c.localS3Hosts, h)
			}
		}
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

	// armis:ignore cwe:918 reason:this code IS the SSRF prevention; URL from validated ARMIS_API_URL env var
	// armis:ignore cwe:918 reason:loopback-HTTP carve-out is intentional for local dev/testing only; same gate as before
	if parsedURL.Scheme != schemeHTTPS {
		if !isLoopbackHost(parsedURL.Hostname()) {
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
		DisableRetry:   true, // Streaming bodies cannot be rewound for retry
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

// BaseURL returns the API base URL the client was configured with. Callers
// use it as the scoping key for per-environment on-disk state (e.g. the
// scan-history store) so a token issued for one Armis environment can never
// look up scans from another.
func (c *Client) BaseURL() string {
	return c.baseURL
}

// setAuthHeader sets the Authorization header on a request, but only if the
// request URL uses HTTPS (or localhost for testing). This prevents credential
// exposure over insecure channels.
//
// For JWT auth: sends "Bearer <token>" per RFC 6750
// For Basic auth: sends "Basic <token>" per RFC 7617
//
// SECURITY NOTE: The localhost/127.0.0.1 exception is intentional for local
// development and testing environments where HTTPS certificates are not available.
// Production deployments must always use HTTPS.
func (c *Client) setAuthHeader(ctx context.Context, req *http.Request) error {
	host := req.URL.Hostname()
	scheme := strings.ToLower(req.URL.Scheme)

	// Require HTTPS for non-loopback hosts to protect credentials
	// armis:ignore cwe:918 reason:request URL is constructed from operator-configured base URL, not external input
	// armis:ignore cwe:522 reason:this code IS the credential protection check (HTTPS enforcement)
	if !isLoopbackHost(host) && scheme != schemeHTTPS {
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
	// SBOMFormat selects the SBOM serialization ("cyclonedx" | "spdx"). Empty
	// defaults to CycloneDX server-side.
	SBOMFormat  string
	GenerateVEX bool
}

// StatusCallback is called on each poll with the current scan status.
// It allows callers to react to status changes (e.g., updating a spinner).
type StatusCallback func(status model.IngestStatusData)

// StartIngest performs the optimized split-flow ingest:
//
//  1. POST /api/v1/ingest/presigned-url — reserves a scan_id and returns a
//     pre-signed S3 POST whose policy carries a Content-Length-Range cap.
//  2. Multipart-POST the artifact directly to S3 (bypassing the API).
//  3. POST /api/v1/ingest/scan — confirms the upload and triggers the scan.
//
// The artifact never travels through the API service, which keeps the API
// hot path tiny and removes the upload-size bandwidth tax.
//
// Returns the scan_id reserved at step 1 (and confirmed at step 3).
func (c *Client) StartIngest(ctx context.Context, opts IngestOptions) (string, error) {
	// armis:ignore cwe:770 reason:this IS the resource exhaustion prevention; MaxUploadSize bounds upload size
	if opts.Size > MaxUploadSize {
		return "", fmt.Errorf("upload size (%d bytes) exceeds maximum allowed (%d bytes)", opts.Size, MaxUploadSize)
	}

	uploadCtx, cancel := context.WithTimeout(ctx, c.uploadTimeout)
	defer cancel()

	start := time.Now()

	// Step 1: reserve a scan_id and get the presigned POST.
	presigned, err := c.createPresignedUpload(uploadCtx, opts)
	if err != nil {
		return "", fmt.Errorf("failed to reserve upload: %w", err)
	}

	// Server's content-length-range cap takes precedence over our local limit.
	// Surface a clear error before we waste bandwidth on a doomed upload.
	if presigned.MaxUploadBytes > 0 && opts.Size > presigned.MaxUploadBytes {
		return "", fmt.Errorf(
			"upload size %d bytes exceeds server limit %d bytes",
			opts.Size, presigned.MaxUploadBytes,
		)
	}

	if c.debug {
		fmt.Fprintf(os.Stderr, "\n=== DEBUG: presigned-url scan_id=%s bucket_url=%s max_bytes=%d ===\n",
			presigned.ScanID, presigned.PresignedURL, presigned.MaxUploadBytes)
	}

	// Step 2: multipart-POST the file directly to S3.
	if err := c.uploadToPresignedURL(uploadCtx, presigned, opts.Filename, opts.Data, opts.Size); err != nil {
		elapsed := time.Since(start).Round(time.Millisecond)
		return "", fmt.Errorf("S3 upload failed after %s (size=%s): %w",
			elapsed, formatBytes(opts.Size), err)
	}

	// Step 3: trigger the scan workflow.
	scanResp, err := c.startArtifactScan(uploadCtx, presigned.ScanID, opts)
	if err != nil {
		return "", fmt.Errorf("failed to trigger scan: %w", err)
	}

	return scanResp.ScanID, nil
}

// createPresignedUpload reserves a scan_id on the API and returns the
// presigned S3 POST + policy fields needed for the direct-upload step.
func (c *Client) createPresignedUpload(ctx context.Context, opts IngestOptions) (*model.PresignedUploadResponse, error) {
	endpoint := strings.TrimSuffix(c.baseURL, "/") + "/api/v1/ingest/presigned-url"

	body := model.PresignedUploadRequest{
		TenantID:     opts.TenantID,
		ArtifactType: opts.ArtifactType,
		Filename:     filepath.Base(opts.Filename),
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// armis:ignore cwe:918 reason:baseURL validated in NewClient (HTTPS enforced, no user-controlled URL components)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if err := c.setAuthHeader(ctx, req); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call /presigned-url: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body read-only

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, MaxAPIResponseSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("/presigned-url returned %s: %s",
			resp.Status, strings.TrimSpace(string(respBytes)))
	}

	var result model.PresignedUploadResponse
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return nil, fmt.Errorf("failed to decode /presigned-url response: %w", err)
	}
	if result.PresignedURL == "" || len(result.Fields) == 0 || result.ScanID == "" {
		return nil, fmt.Errorf("/presigned-url returned an incomplete response")
	}
	return &result, nil
}

// uploadToPresignedURL multipart-POSTs the artifact body to S3 using the
// presigned URL + signed form fields. The signed `policy` field embeds the
// content-length-range cap, so S3 rejects oversized uploads at the edge.
//
// Real S3 requires Content-Length on POST (it returns 411 otherwise), so we
// precompute the multipart envelope length and stream the file in the
// middle. Prefix = boundary delimiter + form fields + file part header.
// Suffix = closing boundary. Both are bounded by the number/size of fields,
// not by the file size, so this is safe for multi-GB uploads.
//
// We deliberately do NOT attach an Authorization header — the presigned
// fields carry their own SigV4 credentials and an extra Authorization header
// would invalidate the signature.
func (c *Client) uploadToPresignedURL(ctx context.Context, p *model.PresignedUploadResponse, filename string, data io.Reader, size int64) error {
	if err := c.ValidatePresignedURL(p.PresignedURL); err != nil {
		return fmt.Errorf("invalid presigned URL: %w", err)
	}

	prefix, suffix, contentType, err := buildMultipartEnvelope(p.Fields, filepath.Base(filename))
	if err != nil {
		return fmt.Errorf("failed to build multipart envelope: %w", err)
	}

	body := io.MultiReader(
		bytes.NewReader(prefix),
		data,
		bytes.NewReader(suffix),
	)

	// armis:ignore cwe:918 reason:URL validated by ValidatePresignedURL above (HTTPS + S3 host allowlist)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.PresignedURL, body)
	if err != nil {
		return fmt.Errorf("failed to create S3 request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	// S3 rejects POSTs without a Content-Length. Total = framing + file size.
	req.ContentLength = int64(len(prefix)) + size + int64(len(suffix))

	resp, err := c.uploadHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("S3 transport error (size=%s): %w", formatBytes(size), err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body read-only

	// S3 returns 200 or 204 on success; anything else is a policy/auth failure.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		// armis:ignore cwe:209 reason:body bounded to 4 KiB; presigned URL is not in the body
		s3Body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("S3 rejected upload (status=%s): %s",
			resp.Status, strings.TrimSpace(string(s3Body)))
	}
	return nil
}

// buildMultipartEnvelope constructs the deterministic prefix and suffix
// bytes for a presigned-S3-POST multipart body so the HTTP client can set
// Content-Length up front (real S3 requires it on POST).
//
// The prefix contains the form-field blocks + the file part's
// Content-Disposition/Content-Type header. The suffix is "\r\n--boundary--\r\n":
// the leading CRLF terminates the file-bytes part, and the dashed boundary
// closes the multipart message.
//
// Format reference: RFC 7578 §4.1, RFC 2046 §5.1.1.
func buildMultipartEnvelope(fields map[string]string, filename string) (prefix, suffix []byte, contentType string, err error) {
	var prefixBuf bytes.Buffer
	w := multipart.NewWriter(&prefixBuf)
	contentType = w.FormDataContentType()

	// Form fields first; the file part must be last per the S3 POST policy
	// rules (only fields preceding the `file` part are evaluated against
	// signed conditions).
	for k, v := range fields {
		if err = w.WriteField(k, v); err != nil {
			return nil, nil, "", fmt.Errorf("write field %q: %w", k, err)
		}
	}

	// File part header only — file bytes are streamed separately via
	// io.MultiReader so we never have to buffer GBs of data.
	if _, err = w.CreateFormFile("file", filename); err != nil {
		return nil, nil, "", fmt.Errorf("create file part: %w", err)
	}

	// Hand-craft the closing boundary. The multipart writer would emit
	// `\r\n--boundary--\r\n` if we Close()'d it after the file part *and*
	// it had observed the file bytes (which we deliberately skip — those
	// bytes go through io.MultiReader, not through the writer). Building
	// the closing line ourselves yields exactly the same trailer.
	suffix = []byte("\r\n--" + w.Boundary() + "--\r\n")
	return prefixBuf.Bytes(), suffix, contentType, nil
}

// startArtifactScan calls /api/v1/ingest/scan with the reserved scan_id and
// the scan options. The server head_objects the upload, transitions the
// scan record to INITIATED, and dispatches to Prefect or SQS.
func (c *Client) startArtifactScan(ctx context.Context, scanID string, opts IngestOptions) (*model.IngestUploadResponse, error) {
	endpoint := strings.TrimSuffix(c.baseURL, "/") + "/api/v1/ingest/scan"

	body := model.IngestScanStartRequest{
		ScanID:       scanID,
		TenantID:     opts.TenantID,
		ScanType:     "full", // matches the prior /tar behavior; flag-driven scan_type is a future change
		SBOMGenerate: opts.GenerateSBOM,
		SBOMFormat:   opts.SBOMFormat,
		VEXGenerate:  opts.GenerateVEX,
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// armis:ignore cwe:918 reason:baseURL validated in NewClient (HTTPS enforced)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if err := c.setAuthHeader(ctx, req); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call /scan: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body read-only

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, MaxAPIResponseSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// 409 from /scan means S3 hasn't seen the upload yet. The most likely
		// cause is a partial/interrupted multipart POST, but we surface the
		// server's `detail` for clarity.
		return nil, fmt.Errorf("/scan returned %s: %s",
			resp.Status, strings.TrimSpace(string(respBytes)))
	}

	var result model.IngestUploadResponse
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return nil, fmt.Errorf("failed to decode /scan response: %w", err)
	}
	return &result, nil
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
		// Return a typed APIError (like FetchNormalizedResults) so callers can
		// classify the failure by status code with errors.As rather than by
		// substring-matching the message text.
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, MaxAPIResponseSize))
		return nil, &APIError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(bodyBytes))}
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, MaxAPIResponseSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	var result model.IngestStatusResponse
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
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
				return nil, fmt.Errorf("scan %s (tenant %s) timed out after %v", scanID, tenantID, timeout)
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

			if statusUpper == "COMPLETED" {
				return &status, nil
			}

			if statusUpper == "FAILED" {
				if status.LastError != nil && *status.LastError != "" {
					return nil, fmt.Errorf("scan failed: %s", *status.LastError)
				}
				return nil, fmt.Errorf("scan failed with no error message (scan_id: %s)", scanID)
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
		return nil, &APIError{StatusCode: resp.StatusCode, Body: string(bodyBytes)}
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, MaxAPIResponseSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Detect if response was truncated at the limit
	if int64(len(bodyBytes)) >= MaxAPIResponseSize {
		return nil, fmt.Errorf("response too large (exceeded %d MB limit); try reducing --page-limit", MaxAPIResponseSize/(1024*1024))
	}

	if c.debug {
		fmt.Fprintf(os.Stderr, "\n=== DEBUG: Normalized Results API Response ===\n%s\n=== END DEBUG ===\n\n", string(bodyBytes))
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
// armis:ignore cwe:73 reason:baseURL validated at client creation (HTTPS enforced); scanID from our own API response
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

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, MaxAPIResponseSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	var result model.ScanResult
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
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
			fmt.Fprintf(os.Stderr, "\n=== DEBUG: FetchArtifactScanResults returned 404 for scan_id=%s ===\n", scanID)
		}
		return nil, nil // Results not yet available
	}

	// Use LimitReader to prevent memory exhaustion from large responses
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, MaxAPIResponseSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if c.debug {
		fmt.Fprintf(os.Stderr, "\n=== DEBUG: Artifact Scan Results API Response ===\n%s\n=== END DEBUG ===\n\n", string(bodyBytes))
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
//
// This function is a critical security control that prevents Server-Side Request
// Forgery (SSRF) attacks by ensuring presigned URLs only point to trusted S3
// endpoints. It enforces HTTPS to protect AWS authentication signatures from
// being exposed over cleartext channels.
//
// Validation rules (in order of precedence):
//  1. Localhost/127.0.0.1: Only allowed if c.allowLocalURLs is true (test-only)
//  2. HTTP URLs: Only allowed if host:port exactly matches c.localS3Hosts allowlist
//  3. HTTPS URLs: Must match *.s3*.amazonaws.com pattern (standard AWS S3)
//  4. All other URLs: Rejected
//
// Local development bypass:
// The c.localS3Hosts allowlist enables HTTP access to mock S3 services during
// local development. This bypass is ONLY enabled when:
//   - ARMIS_LOCAL_S3_ENDPOINT environment variable is set
//   - AND the API base URL is localhost or RFC 1918 private IP
//   - See clientOptionsForBaseURL in cmd/root.go for details
//
// Security properties:
//   - Default deny: URLs are rejected unless they match a specific allow rule
//   - Exact matching: localS3Hosts uses strings.EqualFold for exact host:port match
//   - No wildcards: Cannot use patterns like "*.local:4566"
//   - Port included: "host:4566" and "host:4567" are different entries
//   - Case insensitive: "Host:4566" matches "host:4566"
//
// Example allowed URLs:
//   - https://bucket.s3.amazonaws.com/key
//   - https://bucket.s3.us-west-2.amazonaws.com/key
//   - http://awsmock-dev:4566/bucket/key (if in localS3Hosts)
//
// Example rejected URLs:
//   - http://attacker.com/steal?token=...
//   - https://not-s3.amazonaws.com/bucket/key
//   - http://192.168.1.1/internal-api
func (c *Client) ValidatePresignedURL(presignedURL string) error {
	parsed, err := url.Parse(presignedURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// Extract and normalize URL components for comparison
	// Hostname() returns the host without port; Host includes port
	host := strings.ToLower(parsed.Hostname())
	scheme := strings.ToLower(parsed.Scheme)

	// RULE 1: Localhost URLs (testing only)
	// Only allow loopback hosts (localhost, 127.0.0.0/8, ::1 and all its
	// IPv6 alias forms) if explicitly enabled (for testing only). Using
	// net.ParseIP().IsLoopback inside isLoopbackHost avoids the bypass where
	// an attacker submits "0:0:0:0:0:0:0:1" or similar to dodge a string
	// compare against "::1".
	if isLoopbackHost(host) {
		if c.allowLocalURLs {
			return nil
		}
		return fmt.Errorf("URL host %q is not a recognized S3 endpoint", host)
	}

	// Tests run a single httptest.Server that serves both the API and a fake
	// S3 endpoint. When allowLocalURLs is set AND the configured API base
	// URL is itself loopback, also permit URLs whose host matches the API
	// base URL. The extra base-host loopback gate keeps this shortcut from
	// silently relaxing the SSRF allowlist if anyone ever flipped
	// allowLocalURLs against a non-local base — production builds never set
	// allowLocalURLs, so behavior is unchanged today.
	// armis:ignore cwe:918 reason:this IS the SSRF validation function; allowLocalURLs is never set in production, and even when set both the presigned URL and the API base URL must be loopback (see TestValidatePresignedURL_Regression)
	if c.allowLocalURLs {
		if base, perr := url.Parse(c.baseURL); perr == nil && isLoopbackHost(base.Hostname()) &&
			strings.EqualFold(base.Host, parsed.Host) {
			return nil
		}
	}

	// RULE 2: HTTPS enforcement with local development bypass
	// Presigned URLs contain AWS authentication signatures (X-Amz-Signature) that
	// must be protected from interception. HTTPS is required to prevent signature
	// exposure to network observers.
	// armis:ignore cwe:319 reason:this IS the cleartext transmission prevention (HTTPS enforcement)
	if scheme != schemeHTTPS {
		// HTTP is only allowed for operator-configured mock S3 hosts during local development.
		// The allowlist (c.localS3Hosts) is ONLY populated when the API base URL indicates
		// local development (localhost or RFC 1918 private IPs). For all remote/cloud
		// environments, this slice is empty and all HTTP URLs are rejected.
		//
		// Matching uses parsed.Host (includes port) for exact comparison:
		//   - "awsmock-dev:4566" matches "awsmock-dev:4566" ✓
		//   - "awsmock-dev:4566" DOES NOT match "awsmock-dev:4567" ✗
		//   - "awsmock-dev:4566" DOES NOT match "evil.awsmock-dev:4566" ✗
		//
		// strings.EqualFold provides case-insensitive matching to handle URL
		// variations (e.g., "AwsMock-Dev:4566" matches "awsmock-dev:4566").
		for _, allowed := range c.localS3Hosts {
			if strings.EqualFold(parsed.Host, allowed) {
				// SECURITY: This bypass is safe because:
				// 1. localS3Hosts is only populated for local development URLs
				// 2. Exact match required (no wildcards, includes port)
				// 3. Operator explicitly configured via ARMIS_LOCAL_S3_ENDPOINT
				// armis:ignore cwe:319 reason:opt-in dev-only bypass via ARMIS_LOCAL_S3_ENDPOINT env var
				return nil
			}
		}

		// No match found in allowlist - reject HTTP URL
		// If localS3Hosts is empty (typical for production), this rejects ALL HTTP URLs
		return fmt.Errorf("presigned URL must use HTTPS to protect authentication signatures")
	}

	// Allow standard AWS S3 URL patterns (must contain "s3" and end with ".amazonaws.com"):
	//   - bucket.s3.amazonaws.com (legacy virtual-hosted-style)
	//   - bucket.s3.us-west-2.amazonaws.com (current virtual-hosted-style with region)
	//   - s3.us-west-2.amazonaws.com/bucket (path-style)
	//
	// This intentionally does NOT use wildcards or regex to avoid bypass attacks.
	// armis:ignore cwe:918 reason:this IS the SSRF validation function; allowlisting verified S3 endpoints
	if strings.HasSuffix(host, ".amazonaws.com") && strings.Contains(host, "s3") {
		return nil
	}

	// Reject any URL that doesn't match the rules above
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
	// armis:ignore cwe:918 reason:URL validated by ValidatePresignedURL above (HTTPS + S3 host allowlist)
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
