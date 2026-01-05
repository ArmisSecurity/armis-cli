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
	"strings"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/httpclient"
	"github.com/ArmisSecurity/armis-cli/internal/model"
)

// Client is the API client for communicating with the Armis security service.
type Client struct {
	httpClient       *httpclient.Client
	uploadHTTPClient *httpclient.Client
	baseURL          string
	token            string
	debug            bool
	uploadTimeout    time.Duration
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

// NewClient creates a new API client with the given configuration.
func NewClient(baseURL, token string, debug bool, uploadTimeout time.Duration, opts ...ClientOption) *Client {
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
		token:            token,
		debug:            debug,
		uploadTimeout:    uploadTimeout,
	}

	for _, opt := range opts {
		opt(client)
	}

	return client
}

// IsDebug returns whether debug mode is enabled.
func (c *Client) IsDebug() bool {
	return c.debug
}

// StartIngest uploads an artifact for scanning and returns the scan ID.
func (c *Client) StartIngest(ctx context.Context, tenantID, artifactType, filename string, data io.Reader, size int64) (string, error) {
	uploadCtx, cancel := context.WithTimeout(ctx, c.uploadTimeout)
	defer cancel()

	start := time.Now()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	if err := writer.WriteField("tenant_id", tenantID); err != nil {
		return "", fmt.Errorf("failed to write tenant_id field: %w", err)
	}

	if err := writer.WriteField("artifact_type", artifactType); err != nil {
		return "", fmt.Errorf("failed to write artifact_type field: %w", err)
	}

	if err := writer.WriteField("scan_type", "full"); err != nil {
		return "", fmt.Errorf("failed to write scan_type field: %w", err)
	}

	part, err := writer.CreateFormFile("tar_file", filename)
	if err != nil {
		return "", fmt.Errorf("failed to create form file: %w", err)
	}

	if _, err := io.Copy(part, data); err != nil {
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

	req.Header.Set("Authorization", "Basic "+c.token)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := c.uploadHTTPClient.Do(req)
	if err != nil {
		elapsed := time.Since(start).Round(time.Millisecond)
		return "", fmt.Errorf("upload request failed after %s (tar size=%s): %w", elapsed, formatBytes(size), err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body read-only

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		elapsed := time.Since(start).Round(time.Millisecond)
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("upload failed after %s (tar size=%s, status=%s): %s",
			elapsed, formatBytes(size), resp.Status, strings.TrimSpace(string(bodyBytes)))
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

	req.Header.Set("Authorization", "Basic "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get ingest status: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body read-only

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get status failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result model.IngestStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// WaitForIngest polls until the ingestion is complete or times out.
func (c *Client) WaitForIngest(ctx context.Context, tenantID, scanID string, pollInterval time.Duration, timeout time.Duration) (*model.IngestStatusData, error) {
	if timeout <= 0 {
		timeout = 20 * time.Minute
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

	req.Header.Set("Authorization", "Basic "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch normalized results: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body read-only

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("fetch results failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	bodyBytes, err := io.ReadAll(resp.Body)
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

	req.Header.Set("Authorization", "Basic "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get scan result: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body read-only

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
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
