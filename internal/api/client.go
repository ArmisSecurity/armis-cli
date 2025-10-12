package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/silk-security/Moose-CLI/internal/model"
)

type Client struct {
	httpClient *retryablehttp.Client
	baseURL    string
	token      string
}

func NewClient(baseURL, token string) *Client {
	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 3
	retryClient.RetryWaitMin = 1 * time.Second
	retryClient.RetryWaitMax = 10 * time.Second
	retryClient.Logger = nil

	return &Client{
		httpClient: retryClient,
		baseURL:    baseURL,
		token:      token,
	}
}

func (c *Client) UploadRepo(ctx context.Context, filename string, data io.Reader, size int64) (string, error) {
	return c.uploadFile(ctx, "/scans/repo", filename, data, size)
}

func (c *Client) UploadImage(ctx context.Context, filename string, data io.Reader, size int64) (string, error) {
	return c.uploadFile(ctx, "/scans/image", filename, data, size)
}

func (c *Client) UploadFile(ctx context.Context, filename string, data io.Reader, size int64) (string, error) {
	return c.uploadFile(ctx, "/scans/file", filename, data, size)
}

func (c *Client) uploadFile(ctx context.Context, endpoint, filename string, data io.Reader, size int64) (string, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		return "", fmt.Errorf("failed to create form file: %w", err)
	}

	if _, err := io.Copy(part, data); err != nil {
		return "", fmt.Errorf("failed to copy file data: %w", err)
	}

	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("failed to close multipart writer: %w", err)
	}

	req, err := retryablehttp.NewRequestWithContext(ctx, "POST", c.baseURL+endpoint, body)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
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

	var result struct {
		ScanID string `json:"scan_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return result.ScanID, nil
}

func (c *Client) GetScanResult(ctx context.Context, scanID string) (*model.ScanResult, error) {
	req, err := retryablehttp.NewRequestWithContext(ctx, "GET", c.baseURL+"/scans/"+scanID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)

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
