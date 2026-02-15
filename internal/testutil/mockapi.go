// Package testutil provides utilities for testing.
package testutil

import (
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

// MockAPIConfig configures the mock API server behavior.
type MockAPIConfig struct {
	// Findings to return in normalized-results endpoint
	Findings []model.NormalizedFinding
	// ScanID to use in responses (defaults to "test-scan-001")
	ScanID string
	// PollsUntilComplete is the number of status polls before returning COMPLETED (defaults to 2)
	PollsUntilComplete int
	// FinalStatus is the final scan status (defaults to "COMPLETED")
	FinalStatus string
	// LastError is set when FinalStatus is "FAILED"
	LastError string
}

// NewMockScanServer creates a mock Armis API server for integration testing.
// It handles the full scan flow: upload -> poll status -> fetch results.
func NewMockScanServer(t *testing.T, findings []model.NormalizedFinding) *http.Server {
	return NewMockScanServerWithConfig(t, MockAPIConfig{
		Findings: findings,
	})
}

// NewMockScanServerWithConfig creates a mock Armis API server with custom configuration.
func NewMockScanServerWithConfig(t *testing.T, config MockAPIConfig) *http.Server {
	t.Helper()

	// Apply defaults
	if config.ScanID == "" {
		config.ScanID = "test-scan-001"
	}
	if config.PollsUntilComplete == 0 {
		config.PollsUntilComplete = 2
	}
	if config.FinalStatus == "" {
		config.FinalStatus = "COMPLETED"
	}

	var pollCount int32

	handler := func(w http.ResponseWriter, r *http.Request) {
		// POST /api/v1/ingest/tar - Upload endpoint
		if strings.Contains(r.URL.Path, "/api/v1/ingest/tar") && r.Method == http.MethodPost {
			JSONResponse(t, w, http.StatusOK, model.IngestUploadResponse{
				ScanID:       config.ScanID,
				ArtifactType: "tar",
				TenantID:     "test-tenant",
				Filename:     "upload.tar.gz",
				Message:      "Upload successful",
			})
			return
		}

		// GET /api/v1/ingest/status/{id} - Status polling endpoint
		if strings.Contains(r.URL.Path, "/api/v1/ingest/status") && r.Method == http.MethodGet {
			count := atomic.AddInt32(&pollCount, 1)

			status := "PROCESSING"
			var lastError *string
			if int(count) >= config.PollsUntilComplete {
				status = config.FinalStatus
				if config.FinalStatus == "FAILED" && config.LastError != "" {
					lastError = &config.LastError
				}
			}

			JSONResponse(t, w, http.StatusOK, model.IngestStatusResponse{
				Data: []model.IngestStatusData{
					{
						ScanID:       config.ScanID,
						ScanStatus:   status,
						TenantID:     "test-tenant",
						ArtifactType: "tar",
						ScanType:     "repository",
						LastError:    lastError,
					},
				},
			})
			return
		}

		// GET /api/v1/ingest/normalized-results - Fetch results endpoint
		if strings.Contains(r.URL.Path, "/api/v1/ingest/normalized-results") && r.Method == http.MethodGet {
			JSONResponse(t, w, http.StatusOK, model.NormalizedResultsResponse{
				Data: model.NormalizedResultsData{
					TenantID: "test-tenant",
					ScanResults: []model.ScanResultData{
						{
							ScanID:   config.ScanID,
							ScanTime: 1.5,
							CodeAsset: model.CodeAsset{
								RepositoryName: "test-repo",
								Owner:          "test-owner",
							},
							Findings: config.Findings,
						},
					},
				},
				Pagination: model.Pagination{
					NextCursor: nil,
					Limit:      500,
				},
			})
			return
		}

		// Default: 404 for unknown endpoints
		http.NotFound(w, r)
	}

	server := NewTestServer(t, handler)
	// Return the underlying *http.Server from the httptest.Server
	// Note: NewTestServer returns *httptest.Server which embeds *http.Server
	// We use this type to stay consistent with the helper signature
	return server.Config
}

// GetMockServerURL returns the URL of the mock server for use in tests.
// This is a convenience wrapper that handles the type assertion.
func GetMockServerURL(t *testing.T, findings []model.NormalizedFinding) string {
	t.Helper()
	server := NewTestServer(t, createMockHandler(t, MockAPIConfig{Findings: findings}))
	return server.URL
}

// GetMockServerURLWithConfig returns the URL of the mock server with custom config.
func GetMockServerURLWithConfig(t *testing.T, config MockAPIConfig) string {
	t.Helper()
	server := NewTestServer(t, createMockHandler(t, config))
	return server.URL
}

// createMockHandler creates the HTTP handler for the mock server.
func createMockHandler(t *testing.T, config MockAPIConfig) http.HandlerFunc {
	t.Helper()

	// Apply defaults
	if config.ScanID == "" {
		config.ScanID = "test-scan-001"
	}
	if config.PollsUntilComplete == 0 {
		config.PollsUntilComplete = 2
	}
	if config.FinalStatus == "" {
		config.FinalStatus = "COMPLETED"
	}

	var pollCount int32

	return func(w http.ResponseWriter, r *http.Request) {
		// POST /api/v1/ingest/tar - Upload endpoint
		if strings.Contains(r.URL.Path, "/api/v1/ingest/tar") && r.Method == http.MethodPost {
			JSONResponse(t, w, http.StatusOK, model.IngestUploadResponse{
				ScanID:       config.ScanID,
				ArtifactType: "tar",
				TenantID:     "test-tenant",
				Filename:     "upload.tar.gz",
				Message:      "Upload successful",
			})
			return
		}

		// GET /api/v1/ingest/status/{id} - Status polling endpoint
		if strings.Contains(r.URL.Path, "/api/v1/ingest/status") && r.Method == http.MethodGet {
			count := atomic.AddInt32(&pollCount, 1)

			status := "PROCESSING"
			var lastError *string
			if int(count) >= config.PollsUntilComplete {
				status = config.FinalStatus
				if config.FinalStatus == "FAILED" && config.LastError != "" {
					lastError = &config.LastError
				}
			}

			JSONResponse(t, w, http.StatusOK, model.IngestStatusResponse{
				Data: []model.IngestStatusData{
					{
						ScanID:       config.ScanID,
						ScanStatus:   status,
						TenantID:     "test-tenant",
						ArtifactType: "tar",
						ScanType:     "repository",
						LastError:    lastError,
					},
				},
			})
			return
		}

		// GET /api/v1/ingest/normalized-results - Fetch results endpoint
		if strings.Contains(r.URL.Path, "/api/v1/ingest/normalized-results") && r.Method == http.MethodGet {
			JSONResponse(t, w, http.StatusOK, model.NormalizedResultsResponse{
				Data: model.NormalizedResultsData{
					TenantID: "test-tenant",
					ScanResults: []model.ScanResultData{
						{
							ScanID:   config.ScanID,
							ScanTime: 1.5,
							CodeAsset: model.CodeAsset{
								RepositoryName: "test-repo",
								Owner:          "test-owner",
							},
							Findings: config.Findings,
						},
					},
				},
				Pagination: model.Pagination{
					NextCursor: nil,
					Limit:      500,
				},
			})
			return
		}

		// Default: 404 for unknown endpoints
		http.NotFound(w, r)
	}
}
