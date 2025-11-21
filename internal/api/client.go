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

        "github.com/hashicorp/go-retryablehttp"
        "github.com/silk-security/Moose-CLI/internal/model"
)

type Client struct {
        httpClient *retryablehttp.Client
        baseURL    string
        token      string
        debug      bool
}

func NewClient(baseURL, token string, debug bool) *Client {
        retryClient := retryablehttp.NewClient()
        retryClient.RetryMax = 3
        retryClient.RetryWaitMin = 1 * time.Second
        retryClient.RetryWaitMax = 10 * time.Second
        retryClient.Logger = nil

        return &Client{
                httpClient: retryClient,
                baseURL:    baseURL,
                token:      token,
                debug:      debug,
        }
}

func (c *Client) IsDebug() bool {
        return c.debug
}

func (c *Client) StartIngest(ctx context.Context, tenantID, artifactType, filename string, data io.Reader, size int64) (string, error) {
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
        req, err := retryablehttp.NewRequestWithContext(ctx, "POST", endpoint, body)
        if err != nil {
                return "", fmt.Errorf("failed to create request: %w", err)
        }

        req.Header.Set("Authorization", "Basic "+c.token)
        req.Header.Set("Content-Type", writer.FormDataContentType())

        resp, err := c.httpClient.Do(req)
        if err != nil {
                return "", fmt.Errorf("failed to upload file: %w", err)
        }
        defer resp.Body.Close()

        if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
                bodyBytes, _ := io.ReadAll(resp.Body)
                return "", fmt.Errorf("upload failed with status %d: %s", resp.StatusCode, string(bodyBytes))
        }

        var result model.IngestUploadResponse
        if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
                return "", fmt.Errorf("failed to decode response: %w", err)
        }

        return result.ScanID, nil
}

func (c *Client) GetIngestStatus(ctx context.Context, tenantID, scanID string) (*model.IngestStatusResponse, error) {
        endpoint := strings.TrimSuffix(c.baseURL, "/") + "/api/v1/ingest/status/"
        params := url.Values{}
        params.Add("tenant_id", tenantID)
        params.Add("scan_id", scanID)

        req, err := retryablehttp.NewRequestWithContext(ctx, "GET", endpoint+"?"+params.Encode(), nil)
        if err != nil {
                return nil, fmt.Errorf("failed to create request: %w", err)
        }

        req.Header.Set("Authorization", "Basic "+c.token)

        resp, err := c.httpClient.Do(req)
        if err != nil {
                return nil, fmt.Errorf("failed to get ingest status: %w", err)
        }
        defer resp.Body.Close()

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

func (c *Client) WaitForIngest(ctx context.Context, tenantID, scanID string, pollInterval time.Duration) (*model.IngestStatusData, error) {
        timeoutCtx, cancel := context.WithTimeout(ctx, 20*time.Minute)
        defer cancel()

        ticker := time.NewTicker(pollInterval * time.Second)
        defer ticker.Stop()

        for {
                select {
                case <-timeoutCtx.Done():
                        if timeoutCtx.Err() == context.DeadlineExceeded {
                                return nil, fmt.Errorf("scan timed out after 20 minutes (scan ID: %s)", scanID)
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

        req, err := retryablehttp.NewRequestWithContext(ctx, "GET", endpoint+"?"+params.Encode(), nil)
        if err != nil {
                return nil, fmt.Errorf("failed to create request: %w", err)
        }

        req.Header.Set("Authorization", "Basic "+c.token)

        resp, err := c.httpClient.Do(req)
        if err != nil {
                return nil, fmt.Errorf("failed to fetch normalized results: %w", err)
        }
        defer resp.Body.Close()

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

func (c *Client) GetScanResult(ctx context.Context, scanID string) (*model.ScanResult, error) {
        req, err := retryablehttp.NewRequestWithContext(ctx, "GET", c.baseURL+"/scans/"+scanID, nil)
        if err != nil {
                return nil, fmt.Errorf("failed to create request: %w", err)
        }

        req.Header.Set("Authorization", "Basic "+c.token)

        resp, err := c.httpClient.Do(req)
        if err != nil {
                return nil, fmt.Errorf("failed to get scan result: %w", err)
        }
        defer resp.Body.Close()

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
