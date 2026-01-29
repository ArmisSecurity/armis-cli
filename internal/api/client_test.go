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

// Test constants to satisfy goconst linter.
const (
	testScanID          = "scan-123"
	testMethodGET       = "GET"
	testStatusCompleted = "COMPLETED"
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
				ScanID:       testScanID,
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
		opts := IngestOptions{
			TenantID:     "tenant-456",
			ArtifactType: "image",
			Filename:     "test.tar",
			Data:         data,
			Size:         9,
		}
		scanID, err := client.StartIngest(context.Background(), opts)

		if err != nil {
			t.Fatalf("StartIngest failed: %v", err)
		}
		if scanID != testScanID {
			t.Errorf("Expected scan ID %q, got %s", testScanID, scanID)
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
		opts := IngestOptions{
			TenantID:     "tenant-456",
			ArtifactType: "image",
			Filename:     "test.tar",
			Data:         data,
			Size:         9,
		}
		_, err = client.StartIngest(context.Background(), opts)

		if err == nil {
			t.Error("Expected error for failed upload")
		}
	})

	t.Run("context timeout", func(t *testing.T) {
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(200 * time.Millisecond)
			testutil.JSONResponse(t, w, http.StatusOK, model.IngestUploadResponse{ScanID: testScanID})
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client, err := NewClient(server.URL, "token123", false, 50*time.Millisecond, WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		data := bytes.NewReader([]byte("test data"))
		opts := IngestOptions{
			TenantID:     "tenant-456",
			ArtifactType: "image",
			Filename:     "test.tar",
			Data:         data,
			Size:         9,
		}
		_, err = client.StartIngest(context.Background(), opts)

		if err == nil {
			t.Error("Expected timeout error")
		}
	})

	t.Run("sends SBOM and VEX flags when set", func(t *testing.T) {
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseMultipartForm(32 << 20); err != nil {
				t.Fatalf("Failed to parse multipart form: %v", err)
			}

			// Verify SBOM and VEX generation flags are sent
			if r.FormValue("sbom_generate") != "true" {
				t.Error("Expected sbom_generate=true in form data")
			}
			if r.FormValue("vex_generate") != "true" {
				t.Error("Expected vex_generate=true in form data")
			}

			response := model.IngestUploadResponse{
				ScanID:       testScanID,
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
		opts := IngestOptions{
			TenantID:     "tenant-456",
			ArtifactType: "image",
			Filename:     "test.tar",
			Data:         data,
			Size:         9,
			GenerateSBOM: true,
			GenerateVEX:  true,
		}
		scanID, err := client.StartIngest(context.Background(), opts)

		if err != nil {
			t.Fatalf("StartIngest failed: %v", err)
		}
		if scanID != testScanID {
			t.Errorf("Expected scan ID %q, got %s", testScanID, scanID)
		}
	})
}

func TestClient_GetIngestStatus(t *testing.T) {
	t.Run("successful status check", func(t *testing.T) {
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != testMethodGET {
				t.Errorf("Expected %s, got %s", testMethodGET, r.Method)
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
						ScanStatus: testStatusCompleted,
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
		if status.Data[0].ScanStatus != testStatusCompleted {
			t.Errorf("Expected status %s, got %s", testStatusCompleted, status.Data[0].ScanStatus)
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
			if !strings.Contains(r.URL.Path, "/scans/"+testScanID) {
				t.Errorf("Unexpected path: %s", r.URL.Path)
			}

			response := model.ScanResult{
				ScanID: testScanID,
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

		result, err := client.GetScanResult(context.Background(), testScanID)

		if err != nil {
			t.Fatalf("GetScanResult failed: %v", err)
		}
		if result.ScanID != testScanID {
			t.Errorf("Expected scan ID %q, got %s", testScanID, result.ScanID)
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

func TestClient_FetchArtifactScanResults(t *testing.T) {
	t.Run("successful fetch with SBOM and VEX URLs", func(t *testing.T) {
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != testMethodGET {
				t.Errorf("Expected %s, got %s", testMethodGET, r.Method)
			}
			if !strings.Contains(r.URL.Path, "/api/v1/ingest/results") {
				t.Errorf("Unexpected path: %s", r.URL.Path)
			}

			tenantID := r.URL.Query().Get("tenant_id")
			scanID := r.URL.Query().Get("scan_id")
			if tenantID != "tenant-123" || scanID != "scan-456" {
				t.Errorf("Unexpected query params: tenant_id=%s, scan_id=%s", tenantID, scanID)
			}

			if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
				t.Error("Missing or invalid Authorization header")
			}

			response := ArtifactScanResultsResponse{
				ScanStatus: testStatusCompleted,
				Results: map[string]string{
					"sbom_results": "https://s3.example.com/sbom.json",
					"vex_results":  "https://s3.example.com/vex.json",
				},
			}
			testutil.JSONResponse(t, w, http.StatusOK, response)
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client, err := NewClient(server.URL, "token123", false, 0, WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		result, err := client.FetchArtifactScanResults(context.Background(), "tenant-123", "scan-456")

		if err != nil {
			t.Fatalf("FetchArtifactScanResults failed: %v", err)
		}
		if result == nil {
			t.Fatal("Expected result, got nil")
		}
		if result.ScanStatus != testStatusCompleted {
			t.Errorf("Expected status %s, got %s", testStatusCompleted, result.ScanStatus)
		}
		if result.Results["sbom_results"] != "https://s3.example.com/sbom.json" {
			t.Errorf("Expected SBOM URL, got %s", result.Results["sbom_results"])
		}
		if result.Results["vex_results"] != "https://s3.example.com/vex.json" {
			t.Errorf("Expected VEX URL, got %s", result.Results["vex_results"])
		}
	})

	t.Run("returns nil for 404", func(t *testing.T) {
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client, err := NewClient(server.URL, "token123", false, 0, WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		result, err := client.FetchArtifactScanResults(context.Background(), "tenant-123", "scan-456")

		if err != nil {
			t.Fatalf("Expected no error for 404, got: %v", err)
		}
		if result != nil {
			t.Error("Expected nil result for 404")
		}
	})

	t.Run("returns error for server error", func(t *testing.T) {
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			testutil.ErrorResponse(w, http.StatusInternalServerError, "Internal error")
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client, err := NewClient(server.URL, "token123", false, 0, WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		_, err = client.FetchArtifactScanResults(context.Background(), "tenant-123", "scan-456")

		if err == nil {
			t.Error("Expected error for server error response")
		}
	})
}

func TestClient_DownloadFromPresignedURL(t *testing.T) {
	t.Run("successful download", func(t *testing.T) {
		expectedContent := []byte(`{"sbom": "data", "components": []}`)
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != testMethodGET {
				t.Errorf("Expected %s, got %s", testMethodGET, r.Method)
			}
			// Pre-signed URLs should NOT have authorization headers
			if r.Header.Get("Authorization") != "" {
				t.Error("Should not send auth header to presigned URL")
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(expectedContent)
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client, err := NewClient("https://api.example.com", "token123", false, 0, WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		data, err := client.DownloadFromPresignedURL(context.Background(), server.URL)

		if err != nil {
			t.Fatalf("DownloadFromPresignedURL failed: %v", err)
		}
		if string(data) != string(expectedContent) {
			t.Errorf("Expected %s, got %s", expectedContent, data)
		}
	})

	t.Run("handles download error", func(t *testing.T) {
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client, err := NewClient("https://api.example.com", "token123", false, 0, WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		_, err = client.DownloadFromPresignedURL(context.Background(), server.URL)

		if err == nil {
			t.Error("Expected error for forbidden response")
		}
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(500 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("data"))
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client, err := NewClient("https://api.example.com", "token123", false, 0, WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		_, err = client.DownloadFromPresignedURL(ctx, server.URL)

		if err == nil {
			t.Error("Expected timeout error")
		}
	})

	t.Run("rejects non-S3 URLs", func(t *testing.T) {
		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client, err := NewClient("https://api.example.com", "token123", false, 0, WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		_, err = client.DownloadFromPresignedURL(context.Background(), "https://malicious.example.com/file")

		if err == nil {
			t.Error("Expected error for non-S3 URL")
		}
		if !strings.Contains(err.Error(), "not a recognized S3 endpoint") {
			t.Errorf("Expected S3 endpoint error, got: %v", err)
		}
	})
}

func TestValidatePresignedURL(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		shouldError bool
	}{
		// Valid S3 URLs
		{"S3 bucket URL legacy", "https://mybucket.s3.amazonaws.com/file.json", false},
		{"S3 bucket URL with region", "https://mybucket.s3.us-east-1.amazonaws.com/file.json", false},
		{"S3 path-style URL", "https://s3.us-west-2.amazonaws.com/mybucket/file.json", false},

		// Valid localhost for testing
		{"localhost HTTP", "http://localhost:8080/file", false},
		{"localhost HTTPS", "https://localhost/file", false},
		{"127.0.0.1", "http://127.0.0.1:9000/file", false},

		// Invalid/malicious URLs
		{"non-S3 AWS URL", "https://ec2.amazonaws.com/metadata", true},
		{"arbitrary external URL", "https://malicious.example.com/steal-data", true},
		{"internal service URL", "http://internal.company.local/admin", true},
		{"cloud metadata URL", "http://169.254.169.254/latest/meta-data/", true},
		{"kubernetes API", "https://kubernetes.default.svc/api/v1/secrets", true},

		// Invalid URL formats
		{"empty URL", "", true},
		{"malformed URL", "://invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePresignedURL(tt.url)
			if tt.shouldError && err == nil {
				t.Errorf("Expected error for URL %q, got none", tt.url)
			}
			if !tt.shouldError && err != nil {
				t.Errorf("Unexpected error for URL %q: %v", tt.url, err)
			}
		})
	}
}

func TestClient_StartIngest_SizeLimit(t *testing.T) {
	t.Run("rejects upload exceeding max size", func(t *testing.T) {
		client, err := NewClient("https://api.example.com", "token123", false, 1*time.Minute)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		data := bytes.NewReader([]byte("test"))
		opts := IngestOptions{
			TenantID:     "tenant-456",
			ArtifactType: "image",
			Filename:     "test.tar",
			Data:         data,
			Size:         MaxUploadSize + 1, // Exceeds limit
		}
		_, err = client.StartIngest(context.Background(), opts)

		if err == nil {
			t.Error("Expected error for oversized upload")
		}
		if !strings.Contains(err.Error(), "exceeds maximum allowed") {
			t.Errorf("Expected size limit error, got: %v", err)
		}
	})

	t.Run("accepts upload at max size", func(t *testing.T) {
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			response := model.IngestUploadResponse{ScanID: testScanID}
			testutil.JSONResponse(t, w, http.StatusOK, response)
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client, err := NewClient(server.URL, "token123", false, 1*time.Minute, WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		data := bytes.NewReader([]byte("test"))
		opts := IngestOptions{
			TenantID:     "tenant-456",
			ArtifactType: "image",
			Filename:     "test.tar",
			Data:         data,
			Size:         MaxUploadSize, // Exactly at limit
		}
		_, err = client.StartIngest(context.Background(), opts)

		if err != nil {
			t.Errorf("Should accept upload at max size: %v", err)
		}
	})
}
