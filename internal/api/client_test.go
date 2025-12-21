package api

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/httpclient"
	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/testutil"
)

func TestNewClient(t *testing.T) {
	t.Run("creates client with defaults", func(t *testing.T) {
		client := NewClient("https://api.example.com", "token123", false, 0)

		if client.baseURL != "https://api.example.com" {
			t.Errorf("baseURL mismatch: got %s", client.baseURL)
		}
		if client.token != "token123" {
			t.Errorf("token mismatch: got %s", client.token)
		}
		if client.uploadTimeout != 10*time.Minute {
			t.Errorf("Expected default upload timeout of 10m, got %v", client.uploadTimeout)
		}
	})

	t.Run("uses custom upload timeout", func(t *testing.T) {
		client := NewClient("https://api.example.com", "token123", false, 5*time.Minute)

		if client.uploadTimeout != 5*time.Minute {
			t.Errorf("Expected upload timeout of 5m, got %v", client.uploadTimeout)
		}
	})

	t.Run("accepts custom HTTP client", func(t *testing.T) {
		customClient := httpclient.NewClient(httpclient.Config{Timeout: 30 * time.Second})
		client := NewClient("https://api.example.com", "token123", false, 0, WithHTTPClient(customClient))

		if client.httpClient != customClient {
			t.Error("Custom HTTP client not set")
		}
	})
}

func TestClient_IsDebug(t *testing.T) {
	client := NewClient("https://api.example.com", "token", true, 0)
	if !client.IsDebug() {
		t.Error("Expected debug to be true")
	}

	client2 := NewClient("https://api.example.com", "token", false, 0)
	if client2.IsDebug() {
		t.Error("Expected debug to be false")
	}
}

func TestClient_StartIngest(t *testing.T) {
	t.Run("successful upload", func(t *testing.T) {
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				t.Errorf("Expected POST, got %s", r.Method)
			}
			if !strings.Contains(r.URL.Path, "/api/v1/ingest/tar") {
				t.Errorf("Unexpected path: %s", r.URL.Path)
			}
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
				t.Error("Missing or invalid Authorization header")
			}

			response := model.IngestUploadResponse{
				ScanID:       "scan-123",
				ArtifactType: "image",
				TenantID:     "tenant-456",
				Filename:     "test.tar",
				Message:      "Upload successful",
			}
			testutil.JSONResponse(t, w, http.StatusOK, response)
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client := NewClient(server.URL, "token123", false, 1*time.Minute, WithHTTPClient(httpClient))

		data := bytes.NewReader([]byte("test data"))
		scanID, err := client.StartIngest(context.Background(), "tenant-456", "image", "test.tar", data, 9)

		if err != nil {
			t.Fatalf("StartIngest failed: %v", err)
		}
		if scanID != "scan-123" {
			t.Errorf("Expected scan ID 'scan-123', got %s", scanID)
		}
	})

	t.Run("upload error", func(t *testing.T) {
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			testutil.ErrorResponse(w, http.StatusBadRequest, "Invalid request")
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client := NewClient(server.URL, "token123", false, 1*time.Minute, WithHTTPClient(httpClient))

		data := bytes.NewReader([]byte("test data"))
		_, err := client.StartIngest(context.Background(), "tenant-456", "image", "test.tar", data, 9)

		if err == nil {
			t.Error("Expected error for failed upload")
		}
	})

	t.Run("context timeout", func(t *testing.T) {
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(200 * time.Millisecond)
			testutil.JSONResponse(t, w, http.StatusOK, model.IngestUploadResponse{ScanID: "scan-123"})
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client := NewClient(server.URL, "token123", false, 50*time.Millisecond, WithHTTPClient(httpClient))

		data := bytes.NewReader([]byte("test data"))
		_, err := client.StartIngest(context.Background(), "tenant-456", "image", "test.tar", data, 9)

		if err == nil {
			t.Error("Expected timeout error")
		}
	})
}

func TestClient_GetIngestStatus(t *testing.T) {
	t.Run("successful status check", func(t *testing.T) {
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				t.Errorf("Expected GET, got %s", r.Method)
			}
			if !strings.Contains(r.URL.Path, "/api/v1/ingest/status") {
				t.Errorf("Unexpected path: %s", r.URL.Path)
			}

			tenantID := r.URL.Query().Get("tenant_id")
			scanID := r.URL.Query().Get("scan_id")
			if tenantID != "tenant-123" || scanID != "scan-456" {
				t.Errorf("Unexpected query params: tenant_id=%s, scan_id=%s", tenantID, scanID)
			}

			response := model.IngestStatusResponse{
				Data: []model.IngestStatusData{
					{
						ScanID:     "scan-456",
						ScanStatus: "COMPLETED",
						TenantID:   "tenant-123",
					},
				},
			}
			testutil.JSONResponse(t, w, http.StatusOK, response)
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client := NewClient(server.URL, "token123", false, 0, WithHTTPClient(httpClient))

		status, err := client.GetIngestStatus(context.Background(), "tenant-123", "scan-456")

		if err != nil {
			t.Fatalf("GetIngestStatus failed: %v", err)
		}
		if len(status.Data) != 1 {
			t.Fatalf("Expected 1 status data, got %d", len(status.Data))
		}
		if status.Data[0].ScanStatus != "COMPLETED" {
			t.Errorf("Expected status COMPLETED, got %s", status.Data[0].ScanStatus)
		}
	})

	t.Run("status check error", func(t *testing.T) {
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			testutil.ErrorResponse(w, http.StatusNotFound, "Scan not found")
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client := NewClient(server.URL, "token123", false, 0, WithHTTPClient(httpClient))

		_, err := client.GetIngestStatus(context.Background(), "tenant-123", "scan-456")

		if err == nil {
			t.Error("Expected error for failed status check")
		}
	})
}

func TestClient_FetchNormalizedResults(t *testing.T) {
	t.Run("successful fetch", func(t *testing.T) {
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			if !strings.Contains(r.URL.Path, "/api/v1/ingest/normalized-results") {
				t.Errorf("Unexpected path: %s", r.URL.Path)
			}

			limit := r.URL.Query().Get("limit")
			if limit != "100" {
				t.Errorf("Expected limit=100, got %s", limit)
			}

			nextCursor := "cursor-123"
			response := model.NormalizedResultsResponse{
				Data: model.NormalizedResultsData{
					TenantID: "tenant-123",
					ScanResults: []model.ScanResultData{
						{
							ScanID: "scan-456",
							Findings: []model.NormalizedFinding{
								{
									NormalizedTask: model.NormalizedTask{
										FindingID: "finding-1",
									},
								},
							},
						},
					},
				},
				Pagination: model.Pagination{
					NextCursor: &nextCursor,
					Limit:      100,
				},
			}
			testutil.JSONResponse(t, w, http.StatusOK, response)
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client := NewClient(server.URL, "token123", false, 0, WithHTTPClient(httpClient))

		results, err := client.FetchNormalizedResults(context.Background(), "tenant-123", "scan-456", 100, "")

		if err != nil {
			t.Fatalf("FetchNormalizedResults failed: %v", err)
		}
		if len(results.Data.ScanResults) != 1 {
			t.Fatalf("Expected 1 scan result, got %d", len(results.Data.ScanResults))
		}
		if results.Pagination.NextCursor == nil || *results.Pagination.NextCursor != "cursor-123" {
			t.Error("Expected next cursor")
		}
	})

	t.Run("fetch with cursor", func(t *testing.T) {
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			cursor := r.URL.Query().Get("cursor")
			if cursor != "existing-cursor" {
				t.Errorf("Expected cursor=existing-cursor, got %s", cursor)
			}

			response := model.NormalizedResultsResponse{
				Data: model.NormalizedResultsData{
					TenantID:    "tenant-123",
					ScanResults: []model.ScanResultData{},
				},
				Pagination: model.Pagination{
					NextCursor: nil,
					Limit:      100,
				},
			}
			testutil.JSONResponse(t, w, http.StatusOK, response)
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client := NewClient(server.URL, "token123", false, 0, WithHTTPClient(httpClient))

		_, err := client.FetchNormalizedResults(context.Background(), "tenant-123", "scan-456", 100, "existing-cursor")

		if err != nil {
			t.Fatalf("FetchNormalizedResults failed: %v", err)
		}
	})
}

func TestClient_FetchAllNormalizedResults(t *testing.T) {
	t.Run("fetches all pages", func(t *testing.T) {
		callCount := 0
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			callCount++

			var response model.NormalizedResultsResponse
			if callCount == 1 {
				nextCursor := "cursor-2"
				response = model.NormalizedResultsResponse{
					Data: model.NormalizedResultsData{
						ScanResults: []model.ScanResultData{
							{
								Findings: []model.NormalizedFinding{
									{NormalizedTask: model.NormalizedTask{FindingID: "finding-1"}},
								},
							},
						},
					},
					Pagination: model.Pagination{NextCursor: &nextCursor},
				}
			} else {
				response = model.NormalizedResultsResponse{
					Data: model.NormalizedResultsData{
						ScanResults: []model.ScanResultData{
							{
								Findings: []model.NormalizedFinding{
									{NormalizedTask: model.NormalizedTask{FindingID: "finding-2"}},
								},
							},
						},
					},
					Pagination: model.Pagination{NextCursor: nil},
				}
			}

			testutil.JSONResponse(t, w, http.StatusOK, response)
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client := NewClient(server.URL, "token123", false, 0, WithHTTPClient(httpClient))

		findings, err := client.FetchAllNormalizedResults(context.Background(), "tenant-123", "scan-456", 100)

		if err != nil {
			t.Fatalf("FetchAllNormalizedResults failed: %v", err)
		}
		if len(findings) != 2 {
			t.Errorf("Expected 2 findings, got %d", len(findings))
		}
		if callCount != 2 {
			t.Errorf("Expected 2 API calls, got %d", callCount)
		}
	})
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		name     string
		bytes    int64
		expected string
	}{
		{"zero bytes", 0, "0B"},
		{"bytes", 500, "500B"},
		{"kilobytes", 1024, "1.0KiB"},
		{"megabytes", 1024 * 1024, "1.0MiB"},
		{"gigabytes", 1024 * 1024 * 1024, "1.0GiB"},
		{"mixed", 1536 * 1024, "1.5MiB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatBytes(tt.bytes)
			if result != tt.expected {
				t.Errorf("formatBytes(%d) = %s, want %s", tt.bytes, result, tt.expected)
			}
		})
	}
}

func TestClient_GetScanResult(t *testing.T) {
	t.Run("successful get", func(t *testing.T) {
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			if !strings.Contains(r.URL.Path, "/scans/scan-123") {
				t.Errorf("Unexpected path: %s", r.URL.Path)
			}

			response := model.ScanResult{
				ScanID: "scan-123",
				Status: "completed",
				Findings: []model.Finding{
					{ID: "finding-1", Severity: model.SeverityHigh},
				},
			}
			testutil.JSONResponse(t, w, http.StatusOK, response)
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client := NewClient(server.URL, "token123", false, 0, WithHTTPClient(httpClient))

		result, err := client.GetScanResult(context.Background(), "scan-123")

		if err != nil {
			t.Fatalf("GetScanResult failed: %v", err)
		}
		if result.ScanID != "scan-123" {
			t.Errorf("Expected scan ID 'scan-123', got %s", result.ScanID)
		}
		if result.Status != "completed" {
			t.Errorf("Expected status 'completed', got %s", result.Status)
		}
	})
}

func TestClient_DebugMode(t *testing.T) {
	t.Run("debug mode prints response", func(t *testing.T) {
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			response := model.NormalizedResultsResponse{
				Data: model.NormalizedResultsData{
					TenantID:    "tenant-123",
					ScanResults: []model.ScanResultData{},
				},
				Pagination: model.Pagination{Limit: 100},
			}
			testutil.JSONResponse(t, w, http.StatusOK, response)
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client := NewClient(server.URL, "token123", true, 0, WithHTTPClient(httpClient))

		_, err := client.FetchNormalizedResults(context.Background(), "tenant-123", "scan-456", 100, "")

		if err != nil {
			t.Fatalf("FetchNormalizedResults failed: %v", err)
		}
	})
}
