package image

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/api"
	"github.com/ArmisSecurity/armis-cli/internal/httpclient"
	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/scan/testhelpers"
	"github.com/ArmisSecurity/armis-cli/internal/testutil"
)

const (
	testFindingID               = "finding-1"
	testSQLInjectionDescription = "SQL Injection vulnerability"
)

func TestBuildScanResult(t *testing.T) {
	t.Run("empty findings", func(t *testing.T) {
		result := buildScanResult("scan-123", []model.NormalizedFinding{}, false, true)

		if result.ScanID != "scan-123" {
			t.Errorf("ScanID = %s, want scan-123", result.ScanID)
		}
		if result.Status != "completed" {
			t.Errorf("Status = %s, want completed", result.Status)
		}
		if len(result.Findings) != 0 {
			t.Errorf("Findings count = %d, want 0", len(result.Findings))
		}
		if result.Summary.Total != 0 {
			t.Errorf("Summary.Total = %d, want 0", result.Summary.Total)
		}
		if result.Summary.FilteredNonExploitable != 0 {
			t.Errorf("Summary.FilteredNonExploitable = %d, want 0", result.Summary.FilteredNonExploitable)
		}
	})

	t.Run("multiple findings with different severities and types", func(t *testing.T) {
		findings := []model.NormalizedFinding{
			testhelpers.CreateNormalizedFinding(testFindingID, "CRITICAL", "vulnerability", []string{"CVE-2023-1234"}, nil),
			testhelpers.CreateNormalizedFinding("finding-2", "HIGH", "vulnerability", []string{"CVE-2023-5678"}, nil),
			testhelpers.CreateNormalizedFinding("finding-3", "MEDIUM", "sca", nil, nil),
			testhelpers.CreateNormalizedFinding("finding-4", "LOW", "sca", nil, nil),
			testhelpers.CreateNormalizedFinding("finding-5", "CRITICAL", "vulnerability", []string{"CVE-2023-9999"}, nil),
		}

		result := buildScanResult("scan-456", findings, false, true)

		if result.Summary.Total != 5 {
			t.Errorf("Summary.Total = %d, want 5", result.Summary.Total)
		}
		if result.Summary.BySeverity[model.SeverityCritical] != 2 {
			t.Errorf("BySeverity[CRITICAL] = %d, want 2", result.Summary.BySeverity[model.SeverityCritical])
		}
		if result.Summary.BySeverity[model.SeverityHigh] != 1 {
			t.Errorf("BySeverity[HIGH] = %d, want 1", result.Summary.BySeverity[model.SeverityHigh])
		}
		if result.Summary.BySeverity[model.SeverityMedium] != 1 {
			t.Errorf("BySeverity[MEDIUM] = %d, want 1", result.Summary.BySeverity[model.SeverityMedium])
		}
		if result.Summary.BySeverity[model.SeverityLow] != 1 {
			t.Errorf("BySeverity[LOW] = %d, want 1", result.Summary.BySeverity[model.SeverityLow])
		}
		if result.Summary.ByCategory["vulnerability"] != 3 {
			t.Errorf("ByCategory[vulnerability] = %d, want 3", result.Summary.ByCategory["vulnerability"])
		}
		if result.Summary.ByCategory["sca"] != 2 {
			t.Errorf("ByCategory[sca] = %d, want 2", result.Summary.ByCategory["sca"])
		}
	})

	t.Run("tracks filtered non-exploitable count", func(t *testing.T) {
		findings := []model.NormalizedFinding{
			testhelpers.CreateNormalizedFinding(testFindingID, "HIGH", "vulnerability", []string{"CVE-2023-1234"}, nil),
			testhelpers.CreateNormalizedFindingWithLabels("finding-2", "MEDIUM", "sca", nil, []model.Label{
				{Description: "scanner code", Value: "38295677"},
				{Description: "exploitable", Value: "false"},
			}),
		}

		result := buildScanResult("scan-789", findings, false, false) // includeNonExploitable = false

		if result.Summary.Total != 1 {
			t.Errorf("Summary.Total = %d, want 1", result.Summary.Total)
		}
		if result.Summary.FilteredNonExploitable != 1 {
			t.Errorf("Summary.FilteredNonExploitable = %d, want 1", result.Summary.FilteredNonExploitable)
		}
	})
}

func TestConvertNormalizedFindings(t *testing.T) {
	t.Run("empty input returns empty output", func(t *testing.T) {
		findings, filteredCount := convertNormalizedFindings([]model.NormalizedFinding{}, false, true)

		if len(findings) != 0 {
			t.Errorf("findings count = %d, want 0", len(findings))
		}
		if filteredCount != 0 {
			t.Errorf("filteredCount = %d, want 0", filteredCount)
		}
	})

	t.Run("filters empty findings", func(t *testing.T) {
		input := []model.NormalizedFinding{
			{}, // completely empty
			testhelpers.CreateNormalizedFinding(testFindingID, "HIGH", "vulnerability", []string{"CVE-2023-1234"}, nil),
		}

		findings, _ := convertNormalizedFindings(input, false, true)

		if len(findings) != 1 {
			t.Errorf("findings count = %d, want 1", len(findings))
		}
		if findings[0].ID != testFindingID {
			t.Errorf("finding ID = %s, want testFindingID", findings[0].ID)
		}
	})

	t.Run("filters non-exploitable findings when flag is false", func(t *testing.T) {
		input := []model.NormalizedFinding{
			testhelpers.CreateNormalizedFinding(testFindingID, "HIGH", "vulnerability", []string{"CVE-2023-1234"}, nil),
			testhelpers.CreateNormalizedFindingWithLabels("finding-2", "MEDIUM", "sca", nil, []model.Label{
				{Description: "scanner code", Value: "38295677"},
				{Description: "exploitable", Value: "false"},
			}),
		}

		findings, filteredCount := convertNormalizedFindings(input, false, false)

		if len(findings) != 1 {
			t.Errorf("findings count = %d, want 1", len(findings))
		}
		if filteredCount != 1 {
			t.Errorf("filteredCount = %d, want 1", filteredCount)
		}
	})

	t.Run("keeps non-exploitable findings when flag is true", func(t *testing.T) {
		input := []model.NormalizedFinding{
			testhelpers.CreateNormalizedFinding(testFindingID, "HIGH", "vulnerability", []string{"CVE-2023-1234"}, nil),
			testhelpers.CreateNormalizedFindingWithLabels("finding-2", "MEDIUM", "sca", nil, []model.Label{
				{Description: "scanner code", Value: "38295677"},
				{Description: "exploitable", Value: "false"},
			}),
		}

		findings, filteredCount := convertNormalizedFindings(input, false, true)

		if len(findings) != 2 {
			t.Errorf("findings count = %d, want 2", len(findings))
		}
		if filteredCount != 0 {
			t.Errorf("filteredCount = %d, want 0", filteredCount)
		}
	})

	t.Run("description fallback to long markdown", func(t *testing.T) {
		input := []model.NormalizedFinding{
			{
				NormalizedTask: model.NormalizedTask{
					FindingID: testFindingID,
				},
				NormalizedRemediation: model.NormalizedRemediation{
					Description:     "", // empty primary description
					FindingCategory: "vulnerability",
					VulnerabilityTypeMetadata: model.VulnerabilityTypeMetadata{
						LongDescriptionMarkdown: "Markdown description",
						CVEs:                    []string{"CVE-2023-1234"},
					},
				},
			},
		}

		findings, _ := convertNormalizedFindings(input, false, true)

		if findings[0].Description != "Markdown description" {
			t.Errorf("Description = %q, want %q", findings[0].Description, "Markdown description")
		}
	})

	t.Run("description fallback to task long description", func(t *testing.T) {
		longDesc := "Task long description"
		input := []model.NormalizedFinding{
			{
				NormalizedTask: model.NormalizedTask{
					FindingID:       testFindingID,
					LongDescription: &longDesc,
				},
				NormalizedRemediation: model.NormalizedRemediation{
					FindingCategory: "vulnerability",
					VulnerabilityTypeMetadata: model.VulnerabilityTypeMetadata{
						CVEs: []string{"CVE-2023-1234"},
					},
				},
			},
		}

		findings, _ := convertNormalizedFindings(input, false, true)

		if findings[0].Description != "Task long description" {
			t.Errorf("Description = %q, want %q", findings[0].Description, "Task long description")
		}
	})

	t.Run("maps code location fields", func(t *testing.T) {
		fileName := "/app/main.go"
		startLine := 10
		endLine := 15
		startCol := 5
		endCol := 20
		snippet := "vulnerable code"
		snippetStart := 8

		input := []model.NormalizedFinding{
			{
				NormalizedTask: model.NormalizedTask{
					FindingID: testFindingID,
					ExtraData: model.ExtraData{
						CodeLocation: model.CodeLocation{
							FileName:         &fileName,
							StartLine:        &startLine,
							EndLine:          &endLine,
							StartCol:         &startCol,
							EndCol:           &endCol,
							Snippet:          &snippet,
							SnippetStartLine: &snippetStart,
						},
					},
				},
				NormalizedRemediation: model.NormalizedRemediation{
					Description:     "SQL Injection",
					FindingCategory: "vulnerability",
					VulnerabilityTypeMetadata: model.VulnerabilityTypeMetadata{
						CVEs: []string{"CVE-2023-1234"},
					},
				},
			},
		}

		findings, _ := convertNormalizedFindings(input, false, true)

		f := findings[0]
		if f.File != "/app/main.go" {
			t.Errorf("File = %s, want /app/main.go", f.File)
		}
		if f.StartLine != 10 {
			t.Errorf("StartLine = %d, want 10", f.StartLine)
		}
		if f.EndLine != 15 {
			t.Errorf("EndLine = %d, want 15", f.EndLine)
		}
		if f.StartColumn != 5 {
			t.Errorf("StartColumn = %d, want 5", f.StartColumn)
		}
		if f.EndColumn != 20 {
			t.Errorf("EndColumn = %d, want 20", f.EndColumn)
		}
		if f.CodeSnippet != "vulnerable code" {
			t.Errorf("CodeSnippet = %q, want %q", f.CodeSnippet, "vulnerable code")
		}
		if f.SnippetStartLine != 8 {
			t.Errorf("SnippetStartLine = %d, want 8", f.SnippetStartLine)
		}
	})

	t.Run("code snippet from lines takes precedence", func(t *testing.T) {
		snippet := "single snippet"
		input := []model.NormalizedFinding{
			{
				NormalizedTask: model.NormalizedTask{
					FindingID: testFindingID,
					ExtraData: model.ExtraData{
						CodeLocation: model.CodeLocation{
							CodeSnippetLines: []string{"line 1", "line 2", "line 3"},
							Snippet:          &snippet,
						},
					},
				},
				NormalizedRemediation: model.NormalizedRemediation{
					Description:     "Test finding",
					FindingCategory: "vulnerability",
					VulnerabilityTypeMetadata: model.VulnerabilityTypeMetadata{
						CVEs: []string{"CVE-2023-1234"},
					},
				},
			},
		}

		findings, _ := convertNormalizedFindings(input, false, true)

		expected := "line 1\nline 2\nline 3"
		if findings[0].CodeSnippet != expected {
			t.Errorf("CodeSnippet = %q, want %q", findings[0].CodeSnippet, expected)
		}
	})

	t.Run("finding type determination - CVE means Vulnerability", func(t *testing.T) {
		input := []model.NormalizedFinding{
			testhelpers.CreateNormalizedFinding(testFindingID, "HIGH", "vulnerability", []string{"CVE-2023-1234"}, nil),
		}

		findings, _ := convertNormalizedFindings(input, false, true)

		if findings[0].Type != model.FindingTypeVulnerability {
			t.Errorf("Type = %s, want %s", findings[0].Type, model.FindingTypeVulnerability)
		}
	})

	t.Run("finding type determination - HasSecret means Secret", func(t *testing.T) {
		input := []model.NormalizedFinding{
			{
				NormalizedTask: model.NormalizedTask{
					FindingID: testFindingID,
					ExtraData: model.ExtraData{
						CodeLocation: model.CodeLocation{
							HasSecret: true,
						},
					},
				},
				NormalizedRemediation: model.NormalizedRemediation{
					Description:     "Hardcoded API key",
					FindingCategory: "secret",
				},
			},
		}

		findings, _ := convertNormalizedFindings(input, false, true)

		if findings[0].Type != model.FindingTypeSecret {
			t.Errorf("Type = %s, want %s", findings[0].Type, model.FindingTypeSecret)
		}
	})

	t.Run("finding type determination - default is SCA", func(t *testing.T) {
		input := []model.NormalizedFinding{
			{
				NormalizedTask: model.NormalizedTask{
					FindingID: testFindingID,
				},
				NormalizedRemediation: model.NormalizedRemediation{
					Description:     "Outdated dependency",
					FindingCategory: "sca",
				},
			},
		}

		findings, _ := convertNormalizedFindings(input, false, true)

		if findings[0].Type != model.FindingTypeSCA {
			t.Errorf("Type = %s, want %s", findings[0].Type, model.FindingTypeSCA)
		}
	})

	t.Run("HasSecret overrides CVE type", func(t *testing.T) {
		input := []model.NormalizedFinding{
			{
				NormalizedTask: model.NormalizedTask{
					FindingID: testFindingID,
					ExtraData: model.ExtraData{
						CodeLocation: model.CodeLocation{
							HasSecret: true,
						},
					},
				},
				NormalizedRemediation: model.NormalizedRemediation{
					Description:     "Secret with CVE",
					FindingCategory: "secret",
					VulnerabilityTypeMetadata: model.VulnerabilityTypeMetadata{
						CVEs: []string{"CVE-2023-1234"},
					},
				},
			},
		}

		findings, _ := convertNormalizedFindings(input, false, true)

		// HasSecret is checked after CVE, so it overrides
		if findings[0].Type != model.FindingTypeSecret {
			t.Errorf("Type = %s, want %s", findings[0].Type, model.FindingTypeSecret)
		}
	})

	t.Run("maps CVEs and CWEs", func(t *testing.T) {
		input := []model.NormalizedFinding{
			testhelpers.CreateNormalizedFinding(testFindingID, "HIGH", "vulnerability", []string{"CVE-2023-1234", "CVE-2023-5678"}, []string{"CWE-79", "CWE-89"}),
		}

		findings, _ := convertNormalizedFindings(input, false, true)

		if len(findings[0].CVEs) != 2 {
			t.Errorf("CVEs count = %d, want 2", len(findings[0].CVEs))
		}
		if len(findings[0].CWEs) != 2 {
			t.Errorf("CWEs count = %d, want 2", len(findings[0].CWEs))
		}
	})

	t.Run("title uses description for findings with CVE", func(t *testing.T) {
		input := []model.NormalizedFinding{
			testhelpers.CreateNormalizedFinding(testFindingID, "HIGH", "CODE_VULNERABILITY", []string{"CVE-2023-1234"}, nil),
		}
		input[0].NormalizedRemediation.Description = testSQLInjectionDescription

		findings, _ := convertNormalizedFindings(input, false, true)

		// Findings with CVEs have type=Vulnerability (not SCA), so title uses description
		if findings[0].Title != testSQLInjectionDescription {
			t.Errorf("Title = %q, want %q", findings[0].Title, testSQLInjectionDescription)
		}
	})

	t.Run("title falls back to description when no CVE or OWASP", func(t *testing.T) {
		input := []model.NormalizedFinding{
			testhelpers.CreateNormalizedFinding(testFindingID, "HIGH", "CODE_VULNERABILITY", nil, nil),
		}
		input[0].NormalizedRemediation.Description = testSQLInjectionDescription

		findings, _ := convertNormalizedFindings(input, false, true)

		// Without CVE, should use first sentence of description
		if findings[0].Title != testSQLInjectionDescription {
			t.Errorf("Title = %q, want %q", findings[0].Title, testSQLInjectionDescription)
		}
	})

	t.Run("title falls back to formatted category when no description", func(t *testing.T) {
		input := []model.NormalizedFinding{
			testhelpers.CreateNormalizedFinding(testFindingID, "HIGH", "CODE_VULNERABILITY", nil, nil),
		}
		// Clear the default description from helper
		input[0].NormalizedRemediation.Description = ""

		findings, _ := convertNormalizedFindings(input, false, true)

		// Should fall back to formatted category
		if findings[0].Title != "Code Vulnerability" {
			t.Errorf("Title = %q, want %q", findings[0].Title, "Code Vulnerability")
		}
	})

	t.Run("FindingCategory type assertion - string type", func(t *testing.T) {
		input := []model.NormalizedFinding{
			{
				NormalizedTask: model.NormalizedTask{
					FindingID: testFindingID,
				},
				NormalizedRemediation: model.NormalizedRemediation{
					Description:     "Test finding",
					FindingCategory: "vulnerability", // string type
					VulnerabilityTypeMetadata: model.VulnerabilityTypeMetadata{
						CVEs: []string{"CVE-2023-1234"},
					},
				},
			},
		}

		findings, _ := convertNormalizedFindings(input, false, true)

		if findings[0].FindingCategory != "vulnerability" {
			t.Errorf("FindingCategory = %q, want %q", findings[0].FindingCategory, "vulnerability")
		}
	})

	t.Run("FindingCategory type assertion - nil value", func(t *testing.T) {
		input := []model.NormalizedFinding{
			{
				NormalizedTask: model.NormalizedTask{
					FindingID: testFindingID,
				},
				NormalizedRemediation: model.NormalizedRemediation{
					Description:     "Test finding",
					FindingCategory: nil, // nil value
					VulnerabilityTypeMetadata: model.VulnerabilityTypeMetadata{
						CVEs: []string{"CVE-2023-1234"},
					},
				},
			},
		}

		findings, _ := convertNormalizedFindings(input, false, true)

		if findings[0].FindingCategory != "" {
			t.Errorf("FindingCategory = %q, want empty string", findings[0].FindingCategory)
		}
	})

	t.Run("FindingCategory type assertion - non-string type ignored", func(t *testing.T) {
		input := []model.NormalizedFinding{
			{
				NormalizedTask: model.NormalizedTask{
					FindingID: testFindingID,
				},
				NormalizedRemediation: model.NormalizedRemediation{
					Description:     "Test finding",
					FindingCategory: 12345, // int type - should be ignored
					VulnerabilityTypeMetadata: model.VulnerabilityTypeMetadata{
						CVEs: []string{"CVE-2023-1234"},
					},
				},
			},
		}

		findings, _ := convertNormalizedFindings(input, false, true)

		// Non-string types should result in empty FindingCategory
		if findings[0].FindingCategory != "" {
			t.Errorf("FindingCategory = %q, want empty string for non-string type", findings[0].FindingCategory)
		}
	})
}

func TestScanTarball(t *testing.T) {
	t.Run("successful scan", func(t *testing.T) {
		// Create a temporary tarball
		tmpDir := t.TempDir()
		tarballPath := filepath.Join(tmpDir, "test-image.tar")
		if err := os.WriteFile(tarballPath, []byte("fake tarball content"), 0600); err != nil {
			t.Fatalf("failed to create test tarball: %v", err)
		}

		// Create mock server
		requestCount := 0
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			requestCount++

			switch {
			case strings.Contains(r.URL.Path, "/api/v1/ingest/tar"):
				// StartIngest
				response := model.IngestUploadResponse{
					ScanID:       "scan-123",
					ArtifactType: "image",
					TenantID:     "tenant-456",
					Filename:     "test-image.tar",
					Message:      "Upload successful",
				}
				testutil.JSONResponse(t, w, http.StatusOK, response)

			case strings.Contains(r.URL.Path, "/api/v1/ingest/status"):
				// WaitForIngest
				response := model.IngestStatusResponse{
					Data: []model.IngestStatusData{
						{
							ScanID:     "scan-123",
							ScanStatus: "completed",
						},
					},
				}
				testutil.JSONResponse(t, w, http.StatusOK, response)

			case strings.Contains(r.URL.Path, "/api/v1/ingest/normalized-results"):
				// FetchAllNormalizedResults
				response := model.NormalizedResultsResponse{
					Data: model.NormalizedResultsData{
						TenantID: "tenant-456",
						ScanResults: []model.ScanResultData{
							{
								ScanID: "scan-123",
								Findings: []model.NormalizedFinding{
									{
										NormalizedTask: model.NormalizedTask{
											FindingID: testFindingID,
										},
										NormalizedRemediation: model.NormalizedRemediation{
											ToolSeverity:    "HIGH",
											Description:     "Test vulnerability",
											FindingCategory: "vulnerability",
											VulnerabilityTypeMetadata: model.VulnerabilityTypeMetadata{
												CVEs: []string{"CVE-2023-1234"},
											},
										},
									},
								},
							},
						},
					},
				}
				testutil.JSONResponse(t, w, http.StatusOK, response)

			default:
				t.Errorf("Unexpected request path: %s", r.URL.Path)
				w.WriteHeader(http.StatusNotFound)
			}
		})

		// Create API client pointing to mock server
		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		apiClient, err := api.NewClient(server.URL, testutil.NewTestAuthProvider("token123"), false, 1*time.Minute, api.WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		// Create scanner with mock client
		scanner := NewScanner(apiClient, true, "tenant-456", 100, false, 1*time.Minute, false).WithPollInterval(10 * time.Millisecond)

		// Run scan
		result, err := scanner.ScanTarball(context.Background(), tarballPath)
		if err != nil {
			t.Fatalf("ScanTarball failed: %v", err)
		}

		// Verify result
		if result.ScanID != "scan-123" {
			t.Errorf("ScanID = %s, want scan-123", result.ScanID)
		}
		if result.Status != "completed" {
			t.Errorf("Status = %s, want completed", result.Status)
		}
		if len(result.Findings) != 1 {
			t.Errorf("Findings count = %d, want 1", len(result.Findings))
		}
		if result.Findings[0].ID != testFindingID {
			t.Errorf("Finding ID = %s, want testFindingID", result.Findings[0].ID)
		}
	})

	t.Run("fails for non-existent tarball", func(t *testing.T) {
		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		apiClient, err := api.NewClient("https://localhost", testutil.NewTestAuthProvider("token123"), false, 1*time.Minute, api.WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}
		scanner := NewScanner(apiClient, true, "tenant-456", 100, false, 1*time.Minute, false).WithPollInterval(10 * time.Millisecond)

		_, err = scanner.ScanTarball(context.Background(), "/non/existent/tarball.tar")
		if err == nil {
			t.Error("expected error for non-existent tarball")
		}
		if !strings.Contains(err.Error(), "failed to stat tarball") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("max size limit is defined correctly", func(t *testing.T) {
		// Verify MaxImageSize constant is set to 5GB
		// We can't easily create a 5GB file in tests, but we can verify the constant value
		// and that the size check logic exists in ScanTarball
		expectedMaxSize := int64(5 * 1024 * 1024 * 1024) // 5GB
		if MaxImageSize != expectedMaxSize {
			t.Errorf("MaxImageSize = %d, want %d (5GB)", MaxImageSize, expectedMaxSize)
		}
	})

	t.Run("fails on upload error", func(t *testing.T) {
		tmpDir := t.TempDir()
		tarballPath := filepath.Join(tmpDir, "test-image.tar")
		if err := os.WriteFile(tarballPath, []byte("fake tarball content"), 0600); err != nil {
			t.Fatalf("failed to create test tarball: %v", err)
		}

		server := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			testutil.ErrorResponse(w, http.StatusInternalServerError, "Upload failed")
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second, RetryMax: 1, RetryWaitMin: 10 * time.Millisecond, RetryWaitMax: 50 * time.Millisecond})
		apiClient, err := api.NewClient(server.URL, testutil.NewTestAuthProvider("token123"), false, 1*time.Minute, api.WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}
		scanner := NewScanner(apiClient, true, "tenant-456", 100, false, 1*time.Minute, false).WithPollInterval(10 * time.Millisecond)

		_, err = scanner.ScanTarball(context.Background(), tarballPath)
		if err == nil {
			t.Error("expected error on upload failure")
		}
		if !strings.Contains(err.Error(), "failed to upload image") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("fails on scan timeout", func(t *testing.T) {
		tmpDir := t.TempDir()
		tarballPath := filepath.Join(tmpDir, "test-image.tar")
		if err := os.WriteFile(tarballPath, []byte("fake tarball content"), 0600); err != nil {
			t.Fatalf("failed to create test tarball: %v", err)
		}

		server := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/api/v1/ingest/tar") {
				response := model.IngestUploadResponse{
					ScanID: "scan-123",
				}
				testutil.JSONResponse(t, w, http.StatusOK, response)
			} else if strings.Contains(r.URL.Path, "/api/v1/ingest/status") {
				// Always return processing to simulate timeout
				response := model.IngestStatusResponse{
					Data: []model.IngestStatusData{
						{
							ScanID:     "scan-123",
							ScanStatus: "processing",
						},
					},
				}
				testutil.JSONResponse(t, w, http.StatusOK, response)
			}
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		apiClient, err := api.NewClient(server.URL, testutil.NewTestAuthProvider("token123"), false, 1*time.Minute, api.WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}
		scanner := NewScanner(apiClient, true, "tenant-456", 100, false, 100*time.Millisecond, false) // Very short timeout

		_, err = scanner.ScanTarball(context.Background(), tarballPath)
		if err == nil {
			t.Error("expected timeout error")
		}
	})

	t.Run("fails on fetch results error", func(t *testing.T) {
		tmpDir := t.TempDir()
		tarballPath := filepath.Join(tmpDir, "test-image.tar")
		if err := os.WriteFile(tarballPath, []byte("fake tarball content"), 0600); err != nil {
			t.Fatalf("failed to create test tarball: %v", err)
		}

		server := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/api/v1/ingest/tar"):
				response := model.IngestUploadResponse{ScanID: "scan-123"}
				testutil.JSONResponse(t, w, http.StatusOK, response)
			case strings.Contains(r.URL.Path, "/api/v1/ingest/status"):
				response := model.IngestStatusResponse{
					Data: []model.IngestStatusData{{ScanID: "scan-123", ScanStatus: "completed"}},
				}
				testutil.JSONResponse(t, w, http.StatusOK, response)
			case strings.Contains(r.URL.Path, "/api/v1/ingest/normalized-results"):
				testutil.ErrorResponse(w, http.StatusInternalServerError, "Failed to fetch results")
			}
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second, RetryMax: 1, RetryWaitMin: 10 * time.Millisecond, RetryWaitMax: 50 * time.Millisecond})
		apiClient, err := api.NewClient(server.URL, testutil.NewTestAuthProvider("token123"), false, 1*time.Minute, api.WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}
		scanner := NewScanner(apiClient, true, "tenant-456", 100, false, 1*time.Minute, false).WithPollInterval(10 * time.Millisecond)

		_, err = scanner.ScanTarball(context.Background(), tarballPath)
		if err == nil {
			t.Error("expected error on fetch results failure")
		}
		if !strings.Contains(err.Error(), "failed to fetch results") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		tmpDir := t.TempDir()
		tarballPath := filepath.Join(tmpDir, "test-image.tar")
		if err := os.WriteFile(tarballPath, []byte("fake tarball content"), 0600); err != nil {
			t.Fatalf("failed to create test tarball: %v", err)
		}

		server := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			// Delay to ensure context cancellation takes effect
			time.Sleep(100 * time.Millisecond)
			testutil.JSONResponse(t, w, http.StatusOK, model.IngestUploadResponse{ScanID: "scan-123"})
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		apiClient, err := api.NewClient(server.URL, testutil.NewTestAuthProvider("token123"), false, 1*time.Minute, api.WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}
		scanner := NewScanner(apiClient, true, "tenant-456", 100, false, 1*time.Minute, false).WithPollInterval(10 * time.Millisecond)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		_, err = scanner.ScanTarball(ctx, tarballPath)
		if err == nil {
			t.Error("expected error when context is cancelled")
		}
	})
}

func TestConvertNormalizedFindingsDebugMode(t *testing.T) {
	t.Run("debug mode outputs JSON to stderr", func(t *testing.T) {
		input := []model.NormalizedFinding{
			testhelpers.CreateNormalizedFinding(testFindingID, "HIGH", "vulnerability", []string{"CVE-2023-1234"}, nil),
		}

		// debug=true should print to stderr but not affect the result
		findings, filteredCount := convertNormalizedFindings(input, true, true)

		if len(findings) != 1 {
			t.Errorf("findings count = %d, want 1", len(findings))
		}
		if filteredCount != 0 {
			t.Errorf("filteredCount = %d, want 0", filteredCount)
		}
		if findings[0].ID != testFindingID {
			t.Errorf("finding ID = %s, want testFindingID", findings[0].ID)
		}
	})

	t.Run("debug mode with multiple findings", func(t *testing.T) {
		input := []model.NormalizedFinding{
			testhelpers.CreateNormalizedFinding(testFindingID, "HIGH", "vulnerability", []string{"CVE-2023-1234"}, nil),
			testhelpers.CreateNormalizedFinding("finding-2", "MEDIUM", "sca", []string{"CVE-2023-5678"}, nil),
		}

		findings, _ := convertNormalizedFindings(input, true, true)

		if len(findings) != 2 {
			t.Errorf("findings count = %d, want 2", len(findings))
		}
	})

	t.Run("debug mode skips empty findings", func(t *testing.T) {
		input := []model.NormalizedFinding{
			{}, // empty finding - should be skipped even in debug mode
			testhelpers.CreateNormalizedFinding(testFindingID, "HIGH", "vulnerability", []string{"CVE-2023-1234"}, nil),
		}

		findings, _ := convertNormalizedFindings(input, true, true)

		if len(findings) != 1 {
			t.Errorf("findings count = %d, want 1", len(findings))
		}
	})
}

func TestScanTarballEdgeCases(t *testing.T) {
	t.Run("tarball file does not exist", func(t *testing.T) {
		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		apiClient, _ := api.NewClient("https://example.com", testutil.NewTestAuthProvider("token"), false, time.Minute, api.WithHTTPClient(httpClient))
		scanner := NewScanner(apiClient, true, "tenant-456", 100, false, 1*time.Minute, false)

		_, err := scanner.ScanTarball(context.Background(), "/nonexistent/path/image.tar")
		if err == nil {
			t.Error("Expected error for non-existent tarball")
		}
	})

	t.Run("tarball path is a directory", func(t *testing.T) {
		tmpDir := t.TempDir()

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		apiClient, _ := api.NewClient("https://example.com", testutil.NewTestAuthProvider("token"), false, time.Minute, api.WithHTTPClient(httpClient))
		scanner := NewScanner(apiClient, true, "tenant-456", 100, false, 1*time.Minute, false)

		_, err := scanner.ScanTarball(context.Background(), tmpDir)
		if err == nil {
			t.Error("Expected error when path is a directory")
		}
	})
}
