// Package testutil provides utilities for testing.
package testutil

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

// mockTenantID is the tenant identifier returned by the mock API server.
const mockTenantID = "test-tenant"

// detailKey is the `detail` field of an API error body.
const detailKey = "detail"

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
	// VEXContent, when non-empty, makes GET /api/v1/ingest/results return a
	// vex_results presigned URL that serves this content (used by `scan sbom`).
	VEXContent string
	// SBOMContent, when non-empty, makes GET /api/v1/ingest/results return a
	// sbom_results presigned URL serving this CycloneDX document.
	SBOMContent string
	// SBOMSPDXContent, when non-empty, makes GET /api/v1/ingest/results return
	// a sbom_spdx_results presigned URL serving this SPDX document. Mirrors the
	// backend contract where SPDX lands under its own ref (PPSC-266).
	SBOMSPDXContent string
	// Projects seeds the AppSec projects store behind /api/v1/appsec/projects.
	// The mock behaves like the API: GET filters with `q` as a case-insensitive
	// substring of the name, POST creates a ci_cd project (source "cli") and
	// answers 409 project_name_conflict for a name taken in any status, and
	// names are case-sensitive.
	Projects []model.Project
	// ProjectsDisabled makes every /api/v1/appsec/projects call return the bare
	// 404 the API sends when the AppSec UI is not enabled for the tenant.
	ProjectsDisabled bool
	// Recorder, when set, records every request the mock receives.
	Recorder *RequestRecorder
}

// RecordedRequest is one request seen by the mock API.
type RecordedRequest struct {
	Method string
	Path   string
	Query  url.Values
	// Body is recorded for /api/ requests only (not the S3 upload).
	Body []byte
}

// RequestRecorder collects the requests a mock API receives.
type RequestRecorder struct {
	mu       sync.Mutex
	requests []RecordedRequest
}

// Requests returns a copy of every recorded request, in arrival order.
func (r *RequestRecorder) Requests() []RecordedRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]RecordedRequest(nil), r.requests...)
}

// Matching returns the recorded requests with the given method whose path
// contains pathPart. An empty method matches any method.
func (r *RequestRecorder) Matching(method, pathPart string) []RecordedRequest {
	var out []RecordedRequest
	for _, req := range r.Requests() {
		if (method == "" || req.Method == method) && strings.Contains(req.Path, pathPart) {
			out = append(out, req)
		}
	}
	return out
}

func (r *RequestRecorder) record(req *http.Request) {
	rec := RecordedRequest{Method: req.Method, Path: req.URL.Path, Query: req.URL.Query()}
	if strings.HasPrefix(req.URL.Path, "/api/") && req.Body != nil {
		body, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		_ = req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(body))
		rec.Body = body
	}
	r.mu.Lock()
	r.requests = append(r.requests, rec)
	r.mu.Unlock()
}

// mockProjects is the mock's in-memory AppSec projects store.
type mockProjects struct {
	mu       sync.Mutex
	projects []model.Project
	nextID   int
}

func (m *mockProjects) list(q string, statuses []string) []model.Project {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(statuses) == 0 {
		statuses = []string{model.ProjectStatusActive, model.ProjectStatusPaused}
	}
	var out []model.Project
	for _, p := range m.projects {
		if q != "" && !strings.Contains(strings.ToLower(p.Name), strings.ToLower(q)) {
			continue
		}
		for _, s := range statuses {
			if p.Status == s {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

func (m *mockProjects) create(req model.ProjectCreateRequest) (model.Project, *model.Project) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.projects {
		if m.projects[i].Name == req.Name {
			return model.Project{}, &m.projects[i]
		}
	}
	m.nextID++
	source := "cli"
	p := model.Project{
		ProjectID:   "p_mock" + strconv.Itoa(m.nextID),
		Name:        req.Name,
		Slug:        strings.ToLower(req.Name),
		ProjectType: req.ProjectType,
		Status:      model.ProjectStatusActive,
		Source:      &source,
	}
	m.projects = append(m.projects, p)
	return p, nil
}

func (m *mockProjects) get(id string) (model.Project, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.projects {
		if p.ProjectID == id {
			return p, true
		}
	}
	return model.Project{}, false
}

// handleProjects serves /api/v1/appsec/projects[/{id}] from store.
func handleProjects(t *testing.T, w http.ResponseWriter, r *http.Request, store *mockProjects, disabled bool) {
	t.Helper()
	AssertHasAuthorization(t, r)
	if disabled {
		JSONResponse(t, w, http.StatusNotFound, map[string]string{detailKey: "Not Found"})
		return
	}
	if r.URL.Query().Get("tenant_id") == "" {
		JSONResponse(t, w, http.StatusUnprocessableEntity, map[string]any{
			detailKey: []map[string]any{{"loc": []string{"query", "tenant_id"}, "msg": "Field required"}},
		})
		return
	}

	id := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/api/v1/appsec/projects"), "/")
	switch {
	case id == "" && r.Method == http.MethodGet:
		JSONResponse(t, w, http.StatusOK, model.ProjectListResponse{
			Data:       store.list(r.URL.Query().Get("q"), r.URL.Query()["status"]),
			Pagination: model.ProjectListPagination{Limit: 200},
		})
	case id == "" && r.Method == http.MethodPost:
		var req model.ProjectCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			JSONResponse(t, w, http.StatusUnprocessableEntity, map[string]string{detailKey: err.Error()})
			return
		}
		created, existing := store.create(req)
		if existing != nil {
			JSONResponse(t, w, http.StatusConflict, map[string]any{
				detailKey: "A project named \"" + req.Name + "\" already exists in this tenant.",
				"error":   "project_name_conflict",
				"context": map[string]string{"conflicting_project_id": existing.ProjectID},
			})
			return
		}
		JSONResponse(t, w, http.StatusCreated, created)
	case id != "" && r.Method == http.MethodGet:
		if p, ok := store.get(id); ok {
			JSONResponse(t, w, http.StatusOK, p)
			return
		}
		JSONResponse(t, w, http.StatusNotFound, map[string]string{detailKey: "No such project", "error": "project_not_found"})
	default:
		http.NotFound(w, r)
	}
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
	server := NewTestServer(t, createMockHandler(t, config))
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
	projects := &mockProjects{projects: append([]model.Project(nil), config.Projects...)}

	return func(w http.ResponseWriter, r *http.Request) {
		if config.Recorder != nil {
			config.Recorder.record(r)
		}

		// AppSec projects: GET/POST /api/v1/appsec/projects, GET .../{id}.
		if strings.HasPrefix(r.URL.Path, "/api/v1/appsec/projects") {
			handleProjects(t, w, r, projects, config.ProjectsDisabled)
			return
		}

		// POST /api/v1/ingest/presigned-url — reserves scan_id, returns a
		// presigned POST that points back at this same server's /_s3/... path.
		// `host` is set when the handler runs since httptest's URL is
		// not known at construction time.
		if strings.Contains(r.URL.Path, "/api/v1/ingest/presigned-url") && r.Method == http.MethodPost {
			AssertHasAuthorization(t, r)
			s3URL := SchemeFromRequest(r) + "://" + r.Host + "/_s3/upload"
			JSONResponse(t, w, http.StatusOK, model.PresignedUploadResponse{
				ScanID:       config.ScanID,
				ArtifactType: "repo",
				TenantID:     mockTenantID,
				PresignedURL: s3URL,
				Fields: map[string]string{
					"key":             "ingest/" + mockTenantID + "/" + config.ScanID + "/upload.tar.gz",
					"policy":          "test-policy",
					"x-amz-signature": "test-sig",
				},
				MaxUploadBytes: 2 * 1024 * 1024 * 1024,
				ExpiresIn:      1800,
			})
			return
		}

		// Fake S3 multipart-POST receiver. The CLI's uploadToPresignedURL
		// builds a multipart body; we accept it with 204 to match real S3.
		// AssertValidS3Upload mirrors the real S3 contract (Content-Length,
		// no Authorization header, file part last, etc.) — failures are
		// reported via t.Errorf so envelope drift surfaces as a unit-test
		// failure here instead of a 411 from real S3 in staging.
		if strings.HasPrefix(r.URL.Path, "/_s3/") && r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 64*1024*1024)
			AssertValidS3Upload(t, r)
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// POST /api/v1/ingest/scan — confirms upload and triggers scan.
		if strings.Contains(r.URL.Path, "/api/v1/ingest/scan") && r.Method == http.MethodPost {
			AssertHasAuthorization(t, r)
			JSONResponse(t, w, http.StatusOK, model.IngestUploadResponse{
				ScanID:       config.ScanID,
				ScanStatus:   "INITIATED",
				ArtifactType: "repo",
				TenantID:     mockTenantID,
				Filename:     "upload",
				Message:      "Upload confirmed and scan initiated successfully",
			})
			return
		}

		// Legacy POST /api/v1/ingest/tar kept for any tests that still hit it
		// directly. Newer tests should rely on the split-flow above.
		if strings.Contains(r.URL.Path, "/api/v1/ingest/tar") && r.Method == http.MethodPost {
			JSONResponse(t, w, http.StatusOK, model.IngestUploadResponse{
				ScanID:       config.ScanID,
				ArtifactType: "tar",
				TenantID:     mockTenantID,
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
						TenantID:     mockTenantID,
						ArtifactType: "tar",
						ScanType:     "repository",
						LastError:    lastError,
					},
				},
			})
			return
		}

		// GET /api/v1/ingest/results - artifact results (SBOM/VEX presigned URLs).
		// Returns a vex_results URL pointing back at this same server's /_vex path
		// when VEXContent is configured (used by `scan sbom`).
		if strings.Contains(r.URL.Path, "/api/v1/ingest/results") && r.Method == http.MethodGet {
			AssertHasAuthorization(t, r)
			results := map[string]string{}
			if config.VEXContent != "" {
				results["vex_results"] = SchemeFromRequest(r) + "://" + r.Host + "/_vex/" + config.ScanID
			}
			if config.SBOMContent != "" {
				results["sbom_results"] = SchemeFromRequest(r) + "://" + r.Host + "/_sbom/" + config.ScanID
			}
			if config.SBOMSPDXContent != "" {
				results["sbom_spdx_results"] = SchemeFromRequest(r) + "://" + r.Host + "/_sbom_spdx/" + config.ScanID
			}
			JSONResponse(t, w, http.StatusOK, map[string]interface{}{
				"scan_status": "COMPLETED",
				"results":     results,
			})
			return
		}

		// Fake presigned-URL download endpoint for the VEX document.
		if strings.HasPrefix(r.URL.Path, "/_vex/") && r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(config.VEXContent))
			return
		}

		// Fake presigned-URL download endpoints for the SBOM documents.
		if strings.HasPrefix(r.URL.Path, "/_sbom_spdx/") && r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(config.SBOMSPDXContent))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/_sbom/") && r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(config.SBOMContent))
			return
		}

		// GET /api/v1/ingest/normalized-results - Fetch results endpoint
		if strings.Contains(r.URL.Path, "/api/v1/ingest/normalized-results") && r.Method == http.MethodGet {
			JSONResponse(t, w, http.StatusOK, model.NormalizedResultsResponse{
				Data: model.NormalizedResultsData{
					TenantID: mockTenantID,
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
