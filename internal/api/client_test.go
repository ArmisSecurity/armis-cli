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
		client, err := NewClient("https://api.example.com", "token123", false, 0)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

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
		client, err := NewClient("https://api.example.com", "token123", false, 5*time.Minute)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		if client.uploadTimeout != 5*time.Minute {
			t.Errorf("Expected upload timeout of 5m, got %v", client.uploadTimeout)
		}
	})

	t.Run("accepts custom HTTP client", func(t *testing.T) {
		customClient := httpclient.NewClient(httpclient.Config{Timeout: 30 * time.Second})
		client, err := NewClient("https://api.example.com", "token123", false, 0, WithHTTPClient(customClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		if client.httpClient != customClient {
			t.Error("Custom HTTP client not set")
		}
	})

	t.Run("allows localhost HTTP", func(t *testing.T) {
		client, err := NewClient("http://localhost:8080", "token123", false, 0)
		if err != nil {
			t.Fatalf("NewClient should allow localhost HTTP: %v", err)
		}
		if client == nil {
			t.Error("Expected client to be created")
		}
	})

	t.Run("allows 127.0.0.1 HTTP", func(t *testing.T) {
		client, err := NewClient("http://127.0.0.1:8080", "token123", false, 0)
		if err != nil {
			t.Fatalf("NewClient should allow 127.0.0.1 HTTP: %v", err)
		}
		if client == nil {
			t.Error("Expected client to be created")
		}
	})

	t.Run("rejects non-localhost HTTP", func(t *testing.T) {
		_, err := NewClient("http://api.example.com", "token123", false, 0)
		if err == nil {
			t.Error("Expected error for non-HTTPS non-localhost URL")
		}
	})

	t.Run("rejects invalid URL", func(t *testing.T) {
		_, err := NewClient("://invalid", "token123", false, 0)
		if err == nil {
			t.Error("Expected error for invalid URL")
		}
	})
}

func TestClient_IsDebug(t *testing.T) {
	client, err := NewClient("https://api.example.com", "token", true, 0)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	if !client.IsDebug() {
		t.Error("Expected debug to be true")
	}

	client2, err := NewClient("https://api.example.com", "token", false, 0)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
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
		client, err := NewClient(server.URL, "token123", false, 1*time.Minute, WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

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
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			testutil.ErrorResponse(w, http.StatusBadRequest, "Invalid request")
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client, err := NewClient(server.URL, "token123", false, 1*time.Minute, WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		data := bytes.NewReader([]byte("test data"))
		_, err = client.StartIngest(context.Background(), "tenant-456", "image", "test.tar", data, 9)

		if err == nil {
			t.Error("Expected error for failed upload")
		}
	})

	t.Run("context timeout", func(t *testing.T) {
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(200 * time.Millisecond)
			testutil.JSONResponse(t, w, http.StatusOK, model.IngestUploadResponse{ScanID: "scan-123"})
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client, err := NewClient(server.URL, "token123", false, 50*time.Millisecond, WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		data := bytes.NewReader([]byte("test data"))
		_, err = client.StartIngest(context.Background(), "tenant-456", "image", "test.tar", data, 9)

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
		client, err := NewClient(server.URL, "token123", false, 0, WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

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
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			testutil.ErrorResponse(w, http.StatusNotFound, "Scan not found")
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client, err := NewClient(server.URL, "token123", false, 0, WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		_, err = client.GetIngestStatus(context.Background(), "tenant-123", "scan-456")

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
		client, err := NewClient(server.URL, "token123", false, 0, WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

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
		client, err := NewClient(server.URL, "token123", false, 0, WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		_, err = client.FetchNormalizedResults(context.Background(), "tenant-123", "scan-456", 100, "existing-cursor")

		if err != nil {
			t.Fatalf("FetchNormalizedResults failed: %v", err)
		}
	})
}

func TestClient_FetchAllNormalizedResults(t *testing.T) {
	t.Run("fetches all pages", func(t *testing.T) {
		callCount := 0
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
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
		client, err := NewClient(server.URL, "token123", false, 0, WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

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
		client, err := NewClient(server.URL, "token123", false, 0, WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

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
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
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
		client, err := NewClient(server.URL, "token123", true, 0, WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		_, err = client.FetchNormalizedResults(context.Background(), "tenant-123", "scan-456", 100, "")

		if err != nil {
			t.Fatalf("FetchNormalizedResults failed: %v", err)
		}
	})
}

func TestClient_WaitForIngest(t *testing.T) {
	t.Run("successful completion", func(t *testing.T) {
		callCount := 0
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			callCount++
			var status string
			if callCount < 2 {
				status = "PROCESSING"
			} else {
				status = "COMPLETED"
			}
			response := model.IngestStatusResponse{
				Data: []model.IngestStatusData{
					{
						ScanID:     "scan-123",
						ScanStatus: status,
						TenantID:   "tenant-456",
					},
				},
			}
			testutil.JSONResponse(t, w, http.StatusOK, response)
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client, err := NewClient(server.URL, "token123", false, 0, WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		result, err := client.WaitForIngest(context.Background(), "tenant-456", "scan-123", 10*time.Millisecond, 5*time.Second)

		if err != nil {
			t.Fatalf("WaitForIngest failed: %v", err)
		}
		if result.ScanStatus != "COMPLETED" {
			t.Errorf("Expected status COMPLETED, got %s", result.ScanStatus)
		}
		if callCount < 2 {
			t.Errorf("Expected at least 2 calls, got %d", callCount)
		}
	})

	t.Run("handles FAILED status with error", func(t *testing.T) {
		errorMsg := "Scan processing failed"
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			response := model.IngestStatusResponse{
				Data: []model.IngestStatusData{
					{
						ScanID:     "scan-123",
						ScanStatus: "FAILED",
						TenantID:   "tenant-456",
						LastError:  &errorMsg,
					},
				},
			}
			testutil.JSONResponse(t, w, http.StatusOK, response)
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client, err := NewClient(server.URL, "token123", false, 0, WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		_, err = client.WaitForIngest(context.Background(), "tenant-456", "scan-123", 10*time.Millisecond, 5*time.Second)

		if err == nil {
			t.Fatal("Expected error for FAILED status")
		}
		if !strings.Contains(err.Error(), "scan failed") {
			t.Errorf("Expected 'scan failed' error, got: %v", err)
		}
	})

	t.Run("handles FAILED status without error message", func(t *testing.T) {
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			response := model.IngestStatusResponse{
				Data: []model.IngestStatusData{
					{
						ScanID:     "scan-123",
						ScanStatus: "FAILED",
						TenantID:   "tenant-456",
						LastError:  nil,
					},
				},
			}
			testutil.JSONResponse(t, w, http.StatusOK, response)
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client, err := NewClient(server.URL, "token123", false, 0, WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		result, err := client.WaitForIngest(context.Background(), "tenant-456", "scan-123", 10*time.Millisecond, 5*time.Second)

		if err != nil {
			t.Fatalf("WaitForIngest failed: %v", err)
		}
		if result.ScanStatus != "FAILED" {
			t.Errorf("Expected status FAILED, got %s", result.ScanStatus)
		}
	})

	t.Run("timeout after deadline", func(t *testing.T) {
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			response := model.IngestStatusResponse{
				Data: []model.IngestStatusData{
					{
						ScanID:     "scan-123",
						ScanStatus: "PROCESSING",
						TenantID:   "tenant-456",
					},
				},
			}
			testutil.JSONResponse(t, w, http.StatusOK, response)
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client, err := NewClient(server.URL, "token123", false, 0, WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		_, err = client.WaitForIngest(context.Background(), "tenant-456", "scan-123", 10*time.Millisecond, 50*time.Millisecond)

		if err == nil {
			t.Fatal("Expected timeout error")
		}
		// Error can be "timed out" or "context deadline exceeded"
		if !strings.Contains(err.Error(), "timed out") && !strings.Contains(err.Error(), "deadline exceeded") {
			t.Errorf("Expected timeout error, got: %v", err)
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			response := model.IngestStatusResponse{
				Data: []model.IngestStatusData{
					{
						ScanID:     "scan-123",
						ScanStatus: "PROCESSING",
						TenantID:   "tenant-456",
					},
				},
			}
			testutil.JSONResponse(t, w, http.StatusOK, response)
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client, err := NewClient(server.URL, "token123", false, 0, WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(30 * time.Millisecond)
			cancel()
		}()

		_, err = client.WaitForIngest(ctx, "tenant-456", "scan-123", 10*time.Millisecond, 5*time.Second)

		if err == nil {
			t.Fatal("Expected context cancellation error")
		}
	})

	t.Run("empty status data", func(t *testing.T) {
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			response := model.IngestStatusResponse{
				Data: []model.IngestStatusData{},
			}
			testutil.JSONResponse(t, w, http.StatusOK, response)
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client, err := NewClient(server.URL, "token123", false, 0, WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		_, err = client.WaitForIngest(context.Background(), "tenant-456", "scan-123", 10*time.Millisecond, 5*time.Second)

		if err == nil {
			t.Fatal("Expected error for empty status data")
		}
		if !strings.Contains(err.Error(), "no status data") {
			t.Errorf("Expected 'no status data' error, got: %v", err)
		}
	})

	t.Run("status check error", func(t *testing.T) {
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			testutil.ErrorResponse(w, http.StatusInternalServerError, "Server error")
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 500 * time.Millisecond})
		client, err := NewClient(server.URL, "token123", false, 0, WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		_, err = client.WaitForIngest(context.Background(), "tenant-456", "scan-123", 10*time.Millisecond, 100*time.Millisecond)

		if err == nil {
			t.Fatal("Expected error for failed status check")
		}
	})

	t.Run("lowercase status handling", func(t *testing.T) {
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			response := model.IngestStatusResponse{
				Data: []model.IngestStatusData{
					{
						ScanID:     "scan-123",
						ScanStatus: "completed",
						TenantID:   "tenant-456",
					},
				},
			}
			testutil.JSONResponse(t, w, http.StatusOK, response)
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client, err := NewClient(server.URL, "token123", false, 0, WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		result, err := client.WaitForIngest(context.Background(), "tenant-456", "scan-123", 10*time.Millisecond, 5*time.Second)

		if err != nil {
			t.Fatalf("WaitForIngest failed: %v", err)
		}
		if result == nil {
			t.Fatal("Expected non-nil result")
		}
	})
}

func TestClient_WaitForScan(t *testing.T) {
	t.Run("polls until completed", func(t *testing.T) {
		callCount := 0
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			callCount++
			var status string
			if callCount < 2 {
				status = "processing"
			} else {
				status = "completed"
			}
			response := model.ScanResult{
				ScanID: "scan-123",
				Status: status,
			}
			testutil.JSONResponse(t, w, http.StatusOK, response)
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client, err := NewClient(server.URL, "token123", false, 0, WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		result, err := client.WaitForScan(context.Background(), "scan-123", 10*time.Millisecond)

		if err != nil {
			t.Fatalf("WaitForScan failed: %v", err)
		}
		if result.Status != "completed" {
			t.Errorf("Expected status 'completed', got %s", result.Status)
		}
		if callCount < 2 {
			t.Errorf("Expected at least 2 calls, got %d", callCount)
		}
	})

	t.Run("returns on failed status", func(t *testing.T) {
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			response := model.ScanResult{
				ScanID: "scan-123",
				Status: "failed",
			}
			testutil.JSONResponse(t, w, http.StatusOK, response)
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client, err := NewClient(server.URL, "token123", false, 0, WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		result, err := client.WaitForScan(context.Background(), "scan-123", 10*time.Millisecond)

		if err != nil {
			t.Fatalf("WaitForScan failed: %v", err)
		}
		if result.Status != "failed" {
			t.Errorf("Expected status 'failed', got %s", result.Status)
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			response := model.ScanResult{
				ScanID: "scan-123",
				Status: "processing",
			}
			testutil.JSONResponse(t, w, http.StatusOK, response)
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client, err := NewClient(server.URL, "token123", false, 0, WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(30 * time.Millisecond)
			cancel()
		}()

		_, err = client.WaitForScan(ctx, "scan-123", 10*time.Millisecond)

		if err == nil {
			t.Fatal("Expected context cancellation error")
		}
		// Error may be wrapped or direct
		if !strings.Contains(err.Error(), "canceled") {
			t.Errorf("Expected cancellation error, got: %v", err)
		}
	})

	t.Run("get scan result error", func(t *testing.T) {
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			testutil.ErrorResponse(w, http.StatusInternalServerError, "Server error")
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 500 * time.Millisecond})
		client, err := NewClient(server.URL, "token123", false, 0, WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_, err = client.WaitForScan(ctx, "scan-123", 10*time.Millisecond)

		if err == nil {
			t.Fatal("Expected error for failed get scan result")
		}
	})
}
