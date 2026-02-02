package repo

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
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

const testSQLInjectionDescription = "SQL Injection vulnerability"

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
			testhelpers.CreateNormalizedFinding("finding-1", "CRITICAL", "vulnerability", []string{"CVE-2023-1234"}, nil),
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
			testhelpers.CreateNormalizedFinding("finding-1", "HIGH", "vulnerability", []string{"CVE-2023-1234"}, nil),
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
			testhelpers.CreateNormalizedFinding("finding-1", "HIGH", "vulnerability", []string{"CVE-2023-1234"}, nil),
		}

		findings, _ := convertNormalizedFindings(input, false, true)

		if len(findings) != 1 {
			t.Errorf("findings count = %d, want 1", len(findings))
		}
		if findings[0].ID != "finding-1" {
			t.Errorf("finding ID = %s, want finding-1", findings[0].ID)
		}
	})

	t.Run("filters non-exploitable findings when flag is false", func(t *testing.T) {
		input := []model.NormalizedFinding{
			testhelpers.CreateNormalizedFinding("finding-1", "HIGH", "vulnerability", []string{"CVE-2023-1234"}, nil),
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
			testhelpers.CreateNormalizedFinding("finding-1", "HIGH", "vulnerability", []string{"CVE-2023-1234"}, nil),
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
					FindingID: "finding-1",
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
					FindingID:       "finding-1",
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
					FindingID: "finding-1",
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
					FindingID: "finding-1",
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
			testhelpers.CreateNormalizedFinding("finding-1", "HIGH", "vulnerability", []string{"CVE-2023-1234"}, nil),
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
					FindingID: "finding-1",
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
					FindingID: "finding-1",
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
					FindingID: "finding-1",
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
			testhelpers.CreateNormalizedFinding("finding-1", "HIGH", "vulnerability", []string{"CVE-2023-1234", "CVE-2023-5678"}, []string{"CWE-79", "CWE-89"}),
		}

		findings, _ := convertNormalizedFindings(input, false, true)

		if len(findings[0].CVEs) != 2 {
			t.Errorf("CVEs count = %d, want 2", len(findings[0].CVEs))
		}
		if len(findings[0].CWEs) != 2 {
			t.Errorf("CWEs count = %d, want 2", len(findings[0].CWEs))
		}
	})

	t.Run("title prioritizes description over FindingCategory", func(t *testing.T) {
		input := []model.NormalizedFinding{
			testhelpers.CreateNormalizedFinding("finding-1", "HIGH", "CODE_VULNERABILITY", []string{"CVE-2023-1234"}, nil),
		}
		input[0].NormalizedRemediation.Description = testSQLInjectionDescription

		findings, _ := convertNormalizedFindings(input, false, true)

		// New behavior: uses description as fallback for more descriptive titles
		if findings[0].Title != testSQLInjectionDescription {
			t.Errorf("Title = %q, want %q", findings[0].Title, testSQLInjectionDescription)
		}
	})

	t.Run("title falls back to description when FindingCategory is empty", func(t *testing.T) {
		input := []model.NormalizedFinding{
			testhelpers.CreateNormalizedFinding("finding-1", "HIGH", "", []string{"CVE-2023-1234"}, nil),
		}
		input[0].NormalizedRemediation.Description = testSQLInjectionDescription

		findings, _ := convertNormalizedFindings(input, false, true)

		if findings[0].Title != testSQLInjectionDescription {
			t.Errorf("Title = %q, want %q", findings[0].Title, testSQLInjectionDescription)
		}
	})

	t.Run("FindingCategory type assertion - string type", func(t *testing.T) {
		input := []model.NormalizedFinding{
			{
				NormalizedTask: model.NormalizedTask{
					FindingID: "finding-1",
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
					FindingID: "finding-1",
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
					FindingID: "finding-1",
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

func TestFormatElapsed(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		expected string
	}{
		{
			name:     "zero duration",
			duration: 0,
			expected: "0s",
		},
		{
			name:     "seconds only",
			duration: 45 * time.Second,
			expected: "45s",
		},
		{
			name:     "one minute",
			duration: 60 * time.Second,
			expected: "1m 0s",
		},
		{
			name:     "minutes and seconds",
			duration: 125 * time.Second,
			expected: "2m 5s",
		},
		{
			name:     "many minutes",
			duration: 10*time.Minute + 30*time.Second,
			expected: "10m 30s",
		},
		{
			name:     "rounds to nearest second",
			duration: 45*time.Second + 600*time.Millisecond,
			expected: "46s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatElapsed(tt.duration)
			if result != tt.expected {
				t.Errorf("formatElapsed(%v) = %q, want %q", tt.duration, result, tt.expected)
			}
		})
	}
}

// mockFileInfo implements os.FileInfo for testing
type mockFileInfo struct {
	name  string
	isDir bool
}

func (m mockFileInfo) Name() string       { return m.name }
func (m mockFileInfo) Size() int64        { return 0 }
func (m mockFileInfo) Mode() os.FileMode  { return 0 }
func (m mockFileInfo) ModTime() time.Time { return time.Time{} }
func (m mockFileInfo) IsDir() bool        { return m.isDir }
func (m mockFileInfo) Sys() interface{}   { return nil }

func TestShouldSkip(t *testing.T) {
	// Use filepath.Join for cross-platform compatibility
	tests := []struct {
		name         string
		path         string
		isDir        bool
		includeTests bool
		expected     bool
	}{
		{
			name:         "skip .git directory",
			path:         filepath.Join("repo", ".git"),
			isDir:        true,
			includeTests: true,
			expected:     true,
		},
		{
			name:         "skip node_modules directory",
			path:         filepath.Join("repo", "node_modules"),
			isDir:        true,
			includeTests: true,
			expected:     true,
		},
		{
			name:         "skip vendor directory",
			path:         filepath.Join("repo", "vendor"),
			isDir:        true,
			includeTests: true,
			expected:     true,
		},
		{
			name:         "skip __pycache__ directory",
			path:         filepath.Join("repo", "__pycache__"),
			isDir:        true,
			includeTests: true,
			expected:     true,
		},
		{
			name:         "skip build directory",
			path:         filepath.Join("repo", "build"),
			isDir:        true,
			includeTests: true,
			expected:     true,
		},
		{
			name:         "skip .vscode directory",
			path:         filepath.Join("repo", ".vscode"),
			isDir:        true,
			includeTests: true,
			expected:     true,
		},
		{
			name:         "skip tests directory when includeTests is false",
			path:         filepath.Join("repo", "tests"),
			isDir:        true,
			includeTests: false,
			expected:     true,
		},
		{
			name:         "keep tests directory when includeTests is true",
			path:         filepath.Join("repo", "tests"),
			isDir:        true,
			includeTests: true,
			expected:     false,
		},
		{
			name:         "skip __tests__ directory when includeTests is false",
			path:         filepath.Join("repo", "__tests__"),
			isDir:        true,
			includeTests: false,
			expected:     true,
		},
		{
			name:         "skip test file when includeTests is false",
			path:         filepath.Join("repo", "src", "main_test.go"),
			isDir:        false,
			includeTests: false,
			expected:     true,
		},
		{
			name:         "keep test file when includeTests is true",
			path:         filepath.Join("repo", "src", "main_test.go"),
			isDir:        false,
			includeTests: true,
			expected:     false,
		},
		{
			name:         "keep regular source file",
			path:         filepath.Join("repo", "src", "main.go"),
			isDir:        false,
			includeTests: true,
			expected:     false,
		},
		{
			name:         "keep regular directory",
			path:         filepath.Join("repo", "src"),
			isDir:        true,
			includeTests: true,
			expected:     false,
		},
		{
			name:         "skip file inside node_modules",
			path:         filepath.Join("repo", "node_modules", "package", "index.js"),
			isDir:        false,
			includeTests: true,
			expected:     true,
		},
		{
			name:         "skip file inside .git",
			path:         filepath.Join("repo", ".git", "config"),
			isDir:        false,
			includeTests: true,
			expected:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := mockFileInfo{name: filepath.Base(tt.path), isDir: tt.isDir}
			result := shouldSkip(tt.path, info, tt.includeTests)
			if result != tt.expected {
				t.Errorf("shouldSkip(%q, isDir=%v, includeTests=%v) = %v, want %v",
					tt.path, tt.isDir, tt.includeTests, result, tt.expected)
			}
		})
	}
}

func TestCalculateDirSize(t *testing.T) {
	t.Run("calculates size of files", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create test files
		if err := os.WriteFile(filepath.Join(tmpDir, "file1.go"), []byte("package main"), 0600); err != nil {
			t.Fatalf("failed to create file1.go: %v", err)
		}
		if err := os.WriteFile(filepath.Join(tmpDir, "file2.go"), []byte("package main\n\nfunc main() {}"), 0600); err != nil {
			t.Fatalf("failed to create file2.go: %v", err)
		}

		size, err := calculateDirSize(tmpDir, true, nil)
		if err != nil {
			t.Fatalf("calculateDirSize failed: %v", err)
		}

		// Should be 12 + 28 = 40 bytes
		if size != 40 {
			t.Errorf("size = %d, want 40", size)
		}
	})

	t.Run("excludes test files when includeTests is false", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create test files
		if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main"), 0600); err != nil {
			t.Fatalf("failed to create main.go: %v", err)
		}
		if err := os.WriteFile(filepath.Join(tmpDir, "main_test.go"), []byte("package main\n\nfunc TestMain() {}"), 0600); err != nil {
			t.Fatalf("failed to create main_test.go: %v", err)
		}

		sizeWithTests, err := calculateDirSize(tmpDir, true, nil)
		if err != nil {
			t.Fatalf("calculateDirSize with tests failed: %v", err)
		}

		sizeWithoutTests, err := calculateDirSize(tmpDir, false, nil)
		if err != nil {
			t.Fatalf("calculateDirSize without tests failed: %v", err)
		}

		if sizeWithoutTests >= sizeWithTests {
			t.Errorf("size without tests (%d) should be less than with tests (%d)", sizeWithoutTests, sizeWithTests)
		}
		if sizeWithoutTests != 12 { // just main.go
			t.Errorf("size without tests = %d, want 12", sizeWithoutTests)
		}
	})

	t.Run("excludes node_modules directory", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create source file
		if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main"), 0600); err != nil {
			t.Fatalf("failed to create main.go: %v", err)
		}

		// Create node_modules directory with files
		nodeModules := filepath.Join(tmpDir, "node_modules")
		if err := os.MkdirAll(nodeModules, 0750); err != nil {
			t.Fatalf("failed to create node_modules: %v", err)
		}
		if err := os.WriteFile(filepath.Join(nodeModules, "package.json"), []byte(`{"name":"test"}`), 0600); err != nil {
			t.Fatalf("failed to create package.json: %v", err)
		}

		size, err := calculateDirSize(tmpDir, true, nil)
		if err != nil {
			t.Fatalf("calculateDirSize failed: %v", err)
		}

		// Should only count main.go (12 bytes), not node_modules
		if size != 12 {
			t.Errorf("size = %d, want 12 (node_modules should be excluded)", size)
		}
	})

	t.Run("excludes .git directory", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create source file
		if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main"), 0600); err != nil {
			t.Fatalf("failed to create main.go: %v", err)
		}

		// Create .git directory with files
		gitDir := filepath.Join(tmpDir, ".git")
		if err := os.MkdirAll(gitDir, 0750); err != nil {
			t.Fatalf("failed to create .git: %v", err)
		}
		if err := os.WriteFile(filepath.Join(gitDir, "config"), []byte("[core]\nrepositoryformatversion = 0"), 0600); err != nil {
			t.Fatalf("failed to create config: %v", err)
		}

		size, err := calculateDirSize(tmpDir, true, nil)
		if err != nil {
			t.Fatalf("calculateDirSize failed: %v", err)
		}

		// Should only count main.go (12 bytes), not .git
		if size != 12 {
			t.Errorf("size = %d, want 12 (.git should be excluded)", size)
		}
	})

	t.Run("handles nested directories", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create nested structure
		srcDir := filepath.Join(tmpDir, "src", "pkg")
		if err := os.MkdirAll(srcDir, 0750); err != nil {
			t.Fatalf("failed to create src/pkg: %v", err)
		}
		if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main"), 0600); err != nil {
			t.Fatalf("failed to create main.go: %v", err)
		}
		if err := os.WriteFile(filepath.Join(srcDir, "helper.go"), []byte("package pkg"), 0600); err != nil {
			t.Fatalf("failed to create helper.go: %v", err)
		}

		size, err := calculateDirSize(tmpDir, true, nil)
		if err != nil {
			t.Fatalf("calculateDirSize failed: %v", err)
		}

		// Should count both files: 12 + 11 = 23 bytes
		if size != 23 {
			t.Errorf("size = %d, want 23", size)
		}
	})

	t.Run("returns error for non-existent directory", func(t *testing.T) {
		_, err := calculateDirSize("/non/existent/path", true, nil)
		if err == nil {
			t.Error("expected error for non-existent directory")
		}
	})

	t.Run("skips symlinks", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create a regular file
		targetFile := filepath.Join(tmpDir, "target.go")
		targetContent := "package target"
		if err := os.WriteFile(targetFile, []byte(targetContent), 0600); err != nil {
			t.Fatalf("failed to create target.go: %v", err)
		}

		// Create a symlink pointing to the target
		symlinkPath := filepath.Join(tmpDir, "link.go")
		if err := os.Symlink(targetFile, symlinkPath); err != nil {
			t.Fatalf("failed to create symlink: %v", err)
		}

		size, err := calculateDirSize(tmpDir, true, nil)
		if err != nil {
			t.Fatalf("calculateDirSize failed: %v", err)
		}

		// Should only count target.go (14 bytes), not the symlink
		expectedSize := int64(len(targetContent))
		if size != expectedSize {
			t.Errorf("size = %d, want %d (symlink should be excluded)", size, expectedSize)
		}
	})
}

func TestTarGzDirectory(t *testing.T) {
	t.Run("creates valid tar.gz archive", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create test files
		if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main"), 0600); err != nil {
			t.Fatalf("failed to create main.go: %v", err)
		}
		subDir := filepath.Join(tmpDir, "pkg")
		if err := os.MkdirAll(subDir, 0750); err != nil {
			t.Fatalf("failed to create pkg dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(subDir, "helper.go"), []byte("package pkg"), 0600); err != nil {
			t.Fatalf("failed to create helper.go: %v", err)
		}

		scanner := NewScanner(nil, true, "tenant", 100, true, time.Minute, false)

		var buf bytes.Buffer
		err := scanner.tarGzDirectory(tmpDir, &buf, nil)
		if err != nil {
			t.Fatalf("tarGzDirectory failed: %v", err)
		}

		// Verify it's a valid gzip
		gzReader, err := gzip.NewReader(&buf)
		if err != nil {
			t.Fatalf("failed to create gzip reader: %v", err)
		}
		defer gzReader.Close() //nolint:errcheck // test cleanup

		// Read tar contents
		tarReader := tar.NewReader(gzReader)
		files := make(map[string]string)

		for {
			header, err := tarReader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("failed to read tar entry: %v", err)
			}

			if !header.FileInfo().IsDir() {
				content, err := io.ReadAll(tarReader)
				if err != nil {
					t.Fatalf("failed to read file content: %v", err)
				}
				files[header.Name] = string(content)
			}
		}

		// Verify files
		if content, ok := files["main.go"]; !ok {
			t.Error("main.go not found in archive")
		} else if content != "package main" {
			t.Errorf("main.go content = %q, want %q", content, "package main")
		}

		if content, ok := files["pkg/helper.go"]; !ok {
			t.Error("pkg/helper.go not found in archive")
		} else if content != "package pkg" {
			t.Errorf("pkg/helper.go content = %q, want %q", content, "package pkg")
		}
	})

	t.Run("skips symlinks", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create a regular file
		targetFile := filepath.Join(tmpDir, "target.go")
		if err := os.WriteFile(targetFile, []byte("package target"), 0600); err != nil {
			t.Fatalf("failed to create target.go: %v", err)
		}

		// Create a symlink pointing to the target
		symlinkPath := filepath.Join(tmpDir, "link.go")
		if err := os.Symlink(targetFile, symlinkPath); err != nil {
			t.Fatalf("failed to create symlink: %v", err)
		}

		scanner := NewScanner(nil, true, "tenant", 100, true, time.Minute, false)

		var buf bytes.Buffer
		err := scanner.tarGzDirectory(tmpDir, &buf, nil)
		if err != nil {
			t.Fatalf("tarGzDirectory failed: %v", err)
		}

		// Read tar contents
		gzReader, err := gzip.NewReader(&buf)
		if err != nil {
			t.Fatalf("failed to create gzip reader: %v", err)
		}
		defer gzReader.Close() //nolint:errcheck // test cleanup

		tarReader := tar.NewReader(gzReader)
		files := make(map[string]bool)

		for {
			header, err := tarReader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("failed to read tar entry: %v", err)
			}
			files[header.Name] = true
		}

		// Verify target file is included
		if !files["target.go"] {
			t.Error("target.go should be in archive")
		}

		// Verify symlink is NOT included
		if files["link.go"] {
			t.Error("symlink link.go should NOT be in archive")
		}
	})

	t.Run("skips symlinks to directories", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create a regular file in root
		rootFile := filepath.Join(tmpDir, "main.go")
		if err := os.WriteFile(rootFile, []byte("package main"), 0600); err != nil {
			t.Fatalf("failed to create main.go: %v", err)
		}

		// Create a real directory with a file
		realDir := filepath.Join(tmpDir, "realdir")
		if err := os.MkdirAll(realDir, 0750); err != nil {
			t.Fatalf("failed to create realdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(realDir, "helper.go"), []byte("package helper"), 0600); err != nil {
			t.Fatalf("failed to create helper.go: %v", err)
		}

		// Create a symlink pointing to the directory
		symlinkDir := filepath.Join(tmpDir, "linkdir")
		if err := os.Symlink(realDir, symlinkDir); err != nil {
			t.Fatalf("failed to create symlink to directory: %v", err)
		}

		scanner := NewScanner(nil, true, "tenant", 100, true, time.Minute, false)

		var buf bytes.Buffer
		err := scanner.tarGzDirectory(tmpDir, &buf, nil)
		if err != nil {
			t.Fatalf("tarGzDirectory failed: %v", err)
		}

		// Read tar contents
		gzReader, err := gzip.NewReader(&buf)
		if err != nil {
			t.Fatalf("failed to create gzip reader: %v", err)
		}
		defer gzReader.Close() //nolint:errcheck // test cleanup

		tarReader := tar.NewReader(gzReader)
		files := make(map[string]bool)

		for {
			header, err := tarReader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("failed to read tar entry: %v", err)
			}
			files[header.Name] = true
		}

		// Verify real directory contents are included
		if !files["main.go"] {
			t.Error("main.go should be in archive")
		}
		if !files["realdir/helper.go"] {
			t.Error("realdir/helper.go should be in archive")
		}

		// Verify symlinked directory is NOT included
		if files["linkdir"] {
			t.Error("symlinked directory linkdir should NOT be in archive")
		}
		if files["linkdir/helper.go"] {
			t.Error("files inside symlinked directory should NOT be in archive")
		}
	})

	t.Run("skips broken symlinks", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create a regular file
		regularFile := filepath.Join(tmpDir, "regular.go")
		if err := os.WriteFile(regularFile, []byte("package regular"), 0600); err != nil {
			t.Fatalf("failed to create regular.go: %v", err)
		}

		// Create a broken symlink pointing to non-existent target
		brokenSymlink := filepath.Join(tmpDir, "broken.go")
		if err := os.Symlink(filepath.Join(tmpDir, "nonexistent.go"), brokenSymlink); err != nil {
			t.Fatalf("failed to create broken symlink: %v", err)
		}

		scanner := NewScanner(nil, true, "tenant", 100, true, time.Minute, false)

		var buf bytes.Buffer
		err := scanner.tarGzDirectory(tmpDir, &buf, nil)
		if err != nil {
			t.Fatalf("tarGzDirectory failed: %v", err)
		}

		// Read tar contents
		gzReader, err := gzip.NewReader(&buf)
		if err != nil {
			t.Fatalf("failed to create gzip reader: %v", err)
		}
		defer gzReader.Close() //nolint:errcheck // test cleanup

		tarReader := tar.NewReader(gzReader)
		files := make(map[string]bool)

		for {
			header, err := tarReader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("failed to read tar entry: %v", err)
			}
			files[header.Name] = true
		}

		// Verify regular file is included
		if !files["regular.go"] {
			t.Error("regular.go should be in archive")
		}

		// Verify broken symlink is NOT included
		if files["broken.go"] {
			t.Error("broken symlink broken.go should NOT be in archive")
		}
	})

	t.Run("excludes node_modules directory", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create source file
		if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main"), 0600); err != nil {
			t.Fatalf("failed to create main.go: %v", err)
		}

		// Create node_modules directory
		nodeModules := filepath.Join(tmpDir, "node_modules")
		if err := os.MkdirAll(nodeModules, 0750); err != nil {
			t.Fatalf("failed to create node_modules: %v", err)
		}
		if err := os.WriteFile(filepath.Join(nodeModules, "package.json"), []byte(`{}`), 0600); err != nil {
			t.Fatalf("failed to create package.json: %v", err)
		}

		scanner := NewScanner(nil, true, "tenant", 100, true, time.Minute, false)

		var buf bytes.Buffer
		err := scanner.tarGzDirectory(tmpDir, &buf, nil)
		if err != nil {
			t.Fatalf("tarGzDirectory failed: %v", err)
		}

		// Read tar contents
		gzReader, err := gzip.NewReader(&buf)
		if err != nil {
			t.Fatalf("failed to create gzip reader: %v", err)
		}
		defer gzReader.Close() //nolint:errcheck // test cleanup

		tarReader := tar.NewReader(gzReader)
		var foundNodeModules bool

		for {
			header, err := tarReader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("failed to read tar entry: %v", err)
			}

			if header.Name == "node_modules" || header.Name == "node_modules/package.json" {
				foundNodeModules = true
			}
		}

		if foundNodeModules {
			t.Error("node_modules should not be in the archive")
		}
	})

	t.Run("excludes test files when includeTests is false", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create source and test files
		if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main"), 0600); err != nil {
			t.Fatalf("failed to create main.go: %v", err)
		}
		if err := os.WriteFile(filepath.Join(tmpDir, "main_test.go"), []byte("package main"), 0600); err != nil {
			t.Fatalf("failed to create main_test.go: %v", err)
		}

		scanner := NewScanner(nil, true, "tenant", 100, false, time.Minute, false) // includeTests = false

		var buf bytes.Buffer
		err := scanner.tarGzDirectory(tmpDir, &buf, nil)
		if err != nil {
			t.Fatalf("tarGzDirectory failed: %v", err)
		}

		// Read tar contents
		gzReader, err := gzip.NewReader(&buf)
		if err != nil {
			t.Fatalf("failed to create gzip reader: %v", err)
		}
		defer gzReader.Close() //nolint:errcheck // test cleanup

		tarReader := tar.NewReader(gzReader)
		var foundTestFile bool
		var foundMainFile bool

		for {
			header, err := tarReader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("failed to read tar entry: %v", err)
			}

			if header.Name == "main_test.go" {
				foundTestFile = true
			}
			if header.Name == "main.go" {
				foundMainFile = true
			}
		}

		if foundTestFile {
			t.Error("main_test.go should not be in the archive when includeTests is false")
		}
		if !foundMainFile {
			t.Error("main.go should be in the archive")
		}
	})

	t.Run("includes test files when includeTests is true", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create source and test files
		if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main"), 0600); err != nil {
			t.Fatalf("failed to create main.go: %v", err)
		}
		if err := os.WriteFile(filepath.Join(tmpDir, "main_test.go"), []byte("package main"), 0600); err != nil {
			t.Fatalf("failed to create main_test.go: %v", err)
		}

		scanner := NewScanner(nil, true, "tenant", 100, true, time.Minute, false) // includeTests = true

		var buf bytes.Buffer
		err := scanner.tarGzDirectory(tmpDir, &buf, nil)
		if err != nil {
			t.Fatalf("tarGzDirectory failed: %v", err)
		}

		// Read tar contents
		gzReader, err := gzip.NewReader(&buf)
		if err != nil {
			t.Fatalf("failed to create gzip reader: %v", err)
		}
		defer gzReader.Close() //nolint:errcheck // test cleanup

		tarReader := tar.NewReader(gzReader)
		var foundTestFile bool

		for {
			header, err := tarReader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("failed to read tar entry: %v", err)
			}

			if header.Name == "main_test.go" {
				foundTestFile = true
			}
		}

		if !foundTestFile {
			t.Error("main_test.go should be in the archive when includeTests is true")
		}
	})
}

func TestScan(t *testing.T) {
	t.Run("successful scan", func(t *testing.T) {
		// Create a temporary directory with test files
		tmpDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main\n\nfunc main() {}"), 0600); err != nil {
			t.Fatalf("failed to create main.go: %v", err)
		}
		subDir := filepath.Join(tmpDir, "pkg")
		if err := os.MkdirAll(subDir, 0750); err != nil {
			t.Fatalf("failed to create pkg dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(subDir, "helper.go"), []byte("package pkg"), 0600); err != nil {
			t.Fatalf("failed to create helper.go: %v", err)
		}

		// Create mock server
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/api/v1/ingest/tar"):
				// StartIngest
				response := model.IngestUploadResponse{
					ScanID:       "scan-123",
					ArtifactType: "repo",
					TenantID:     "tenant-456",
					Filename:     "test-repo.tar.gz",
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
											FindingID: "finding-1",
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
		apiClient, err := api.NewClient(server.URL, "token123", false, 1*time.Minute, api.WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		// Create scanner with mock client
		scanner := NewScanner(apiClient, true, "tenant-456", 100, true, 1*time.Minute, false).WithPollInterval(10 * time.Millisecond)

		// Run scan
		result, err := scanner.Scan(context.Background(), tmpDir)
		if err != nil {
			t.Fatalf("Scan failed: %v", err)
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
		if result.Findings[0].ID != "finding-1" {
			t.Errorf("Finding ID = %s, want finding-1", result.Findings[0].ID)
		}
	})

	t.Run("fails for non-existent directory", func(t *testing.T) {
		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		apiClient, err := api.NewClient("https://localhost", "token123", false, 1*time.Minute, api.WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}
		scanner := NewScanner(apiClient, true, "tenant-456", 100, true, 1*time.Minute, false).WithPollInterval(10 * time.Millisecond)

		_, err = scanner.Scan(context.Background(), "/non/existent/path")
		if err == nil {
			t.Error("expected error for non-existent directory")
		}
		if !strings.Contains(err.Error(), "failed to stat path") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("fails for file instead of directory", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "file.txt")
		if err := os.WriteFile(tmpFile, []byte("content"), 0600); err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		apiClient, err := api.NewClient("https://localhost", "token123", false, 1*time.Minute, api.WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}
		scanner := NewScanner(apiClient, true, "tenant-456", 100, true, 1*time.Minute, false).WithPollInterval(10 * time.Millisecond)

		_, err = scanner.Scan(context.Background(), tmpFile)
		if err == nil {
			t.Error("expected error for file instead of directory")
		}
		if !strings.Contains(err.Error(), "not a directory") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("fails on upload error", func(t *testing.T) {
		tmpDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main"), 0600); err != nil {
			t.Fatalf("failed to create main.go: %v", err)
		}

		server := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			testutil.ErrorResponse(w, http.StatusInternalServerError, "Upload failed")
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second, RetryMax: 1, RetryWaitMin: 10 * time.Millisecond, RetryWaitMax: 50 * time.Millisecond})
		apiClient, err := api.NewClient(server.URL, "token123", false, 1*time.Minute, api.WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}
		scanner := NewScanner(apiClient, true, "tenant-456", 100, true, 1*time.Minute, false).WithPollInterval(10 * time.Millisecond)

		_, err = scanner.Scan(context.Background(), tmpDir)
		if err == nil {
			t.Error("expected error on upload failure")
		}
		if !strings.Contains(err.Error(), "failed to upload repository") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		tmpDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main"), 0600); err != nil {
			t.Fatalf("failed to create main.go: %v", err)
		}

		server := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			// Delay to ensure context cancellation takes effect
			time.Sleep(100 * time.Millisecond)
			testutil.JSONResponse(t, w, http.StatusOK, model.IngestUploadResponse{ScanID: "scan-123"})
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		apiClient, err := api.NewClient(server.URL, "token123", false, 1*time.Minute, api.WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}
		scanner := NewScanner(apiClient, true, "tenant-456", 100, true, 1*time.Minute, false).WithPollInterval(10 * time.Millisecond)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		_, err = scanner.Scan(ctx, tmpDir)
		if err == nil {
			t.Error("expected error when context is cancelled")
		}
	})
}

func TestIsPathContained(t *testing.T) {
	t.Run("valid contained path", func(t *testing.T) {
		if !isPathContained("/repo", "/repo/src/main.go") {
			t.Error("Expected path to be contained")
		}
	})

	t.Run("nested valid path", func(t *testing.T) {
		if !isPathContained("/repo", "/repo/a/b/c/file.go") {
			t.Error("Expected nested path to be contained")
		}
	})

	t.Run("path escapes with double dots", func(t *testing.T) {
		if isPathContained("/repo", "/repo/../etc/passwd") {
			t.Error("Expected path traversal to be rejected")
		}
	})

	t.Run("absolute path outside base", func(t *testing.T) {
		if isPathContained("/repo", "/etc/passwd") {
			t.Error("Expected absolute path outside base to be rejected")
		}
	})

	t.Run("path at root level", func(t *testing.T) {
		if !isPathContained("/repo", "/repo/file.go") {
			t.Error("Expected file at root level to be contained")
		}
	})

	t.Run("same directory", func(t *testing.T) {
		// The base directory itself should be considered contained
		if !isPathContained("/repo", "/repo") {
			t.Error("Expected base directory itself to be contained")
		}
	})
}

func TestTarGzFiles(t *testing.T) {
	t.Run("creates valid tar.gz with files", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create test files
		if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main"), 0600); err != nil {
			t.Fatalf("failed to create main.go: %v", err)
		}
		if err := os.WriteFile(filepath.Join(tmpDir, "util.go"), []byte("package util"), 0600); err != nil {
			t.Fatalf("failed to create util.go: %v", err)
		}

		scanner := NewScanner(nil, false, "tenant", 100, true, time.Minute, false)

		var buf bytes.Buffer
		err := scanner.tarGzFiles(tmpDir, []string{"main.go", "util.go"}, &buf)
		if err != nil {
			t.Fatalf("tarGzFiles failed: %v", err)
		}

		// Verify it's a valid gzip
		gzReader, err := gzip.NewReader(&buf)
		if err != nil {
			t.Fatalf("failed to read gzip: %v", err)
		}
		defer func() {
			if closeErr := gzReader.Close(); closeErr != nil {
				t.Errorf("failed to close gzip reader: %v", closeErr)
			}
		}()

		// Verify it's a valid tar
		tarReader := tar.NewReader(gzReader)
		fileCount := 0
		for {
			_, err := tarReader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("failed to read tar entry: %v", err)
			}
			fileCount++
		}

		if fileCount != 2 {
			t.Errorf("Expected 2 files in tar, got %d", fileCount)
		}
	})

	t.Run("returns error when no files added", func(t *testing.T) {
		tmpDir := t.TempDir()
		scanner := NewScanner(nil, false, "tenant", 100, true, time.Minute, false)

		var buf bytes.Buffer
		err := scanner.tarGzFiles(tmpDir, []string{}, &buf)

		if err == nil {
			t.Fatal("Expected error when no files to archive")
		}
		if !strings.Contains(err.Error(), "no files were added") {
			t.Errorf("Expected 'no files were added' error, got: %v", err)
		}
	})

	t.Run("skips non-existent files gracefully", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create one valid file
		if err := os.WriteFile(filepath.Join(tmpDir, "exists.go"), []byte("package main"), 0600); err != nil {
			t.Fatalf("failed to create exists.go: %v", err)
		}

		scanner := NewScanner(nil, false, "tenant", 100, true, time.Minute, false)

		var buf bytes.Buffer
		err := scanner.tarGzFiles(tmpDir, []string{"exists.go", "nonexistent.go"}, &buf)

		if err != nil {
			t.Fatalf("tarGzFiles failed: %v", err)
		}
	})

	t.Run("skips directories", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create a file and a subdirectory
		if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main"), 0600); err != nil {
			t.Fatalf("failed to create main.go: %v", err)
		}
		if err := os.MkdirAll(filepath.Join(tmpDir, "subdir"), 0750); err != nil {
			t.Fatalf("failed to create subdir: %v", err)
		}

		scanner := NewScanner(nil, false, "tenant", 100, true, time.Minute, false)

		var buf bytes.Buffer
		err := scanner.tarGzFiles(tmpDir, []string{"main.go", "subdir"}, &buf)

		if err != nil {
			t.Fatalf("tarGzFiles failed: %v", err)
		}
	})

	t.Run("error when all files are non-existent", func(t *testing.T) {
		tmpDir := t.TempDir()
		scanner := NewScanner(nil, false, "tenant", 100, true, time.Minute, false)

		var buf bytes.Buffer
		err := scanner.tarGzFiles(tmpDir, []string{"nonexistent1.go", "nonexistent2.go"}, &buf)

		if err == nil {
			t.Fatal("Expected error when all files are non-existent")
		}
		if !strings.Contains(err.Error(), "no files were added") {
			t.Errorf("Expected 'no files were added' error, got: %v", err)
		}
	})

	t.Run("skips path outside repository", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create a valid file
		if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main"), 0600); err != nil {
			t.Fatalf("failed to create main.go: %v", err)
		}

		scanner := NewScanner(nil, false, "tenant", 100, true, time.Minute, false)

		var buf bytes.Buffer
		// Include a path traversal attempt - this should be skipped
		err := scanner.tarGzFiles(tmpDir, []string{"main.go", "../../../etc/passwd"}, &buf)

		if err != nil {
			t.Fatalf("tarGzFiles failed: %v", err)
		}
	})
}

func TestGenerateFindingTitle(t *testing.T) {
	tests := []struct {
		name     string
		finding  *model.Finding
		expected string
	}{
		// SCA findings with CVE
		{
			name: "SCA with single CVE and package with version",
			finding: &model.Finding{
				Type:    model.FindingTypeSCA,
				CVEs:    []string{"CVE-2023-12345"},
				Package: "lodash",
				Version: "4.17.15",
			},
			expected: "CVE-2023-12345 in lodash@4.17.15",
		},
		{
			name: "SCA with multiple CVEs and package",
			finding: &model.Finding{
				Type:    model.FindingTypeSCA,
				CVEs:    []string{"CVE-2023-1111", "CVE-2023-2222", "CVE-2023-3333"},
				Package: "express",
				Version: "4.18.0",
			},
			expected: "CVE-2023-1111 (+2 more) in express@4.18.0",
		},
		{
			name: "SCA with CVE but no package info",
			finding: &model.Finding{
				Type: model.FindingTypeSCA,
				CVEs: []string{"CVE-2023-99999"},
			},
			expected: "CVE-2023-99999",
		},
		{
			name: "SCA with CVE and package but no version",
			finding: &model.Finding{
				Type:    model.FindingTypeSCA,
				CVEs:    []string{"CVE-2023-44444"},
				Package: "axios",
			},
			expected: "CVE-2023-44444 in axios",
		},
		{
			name: "SCA without CVEs falls through to next priority",
			finding: &model.Finding{
				Type:        model.FindingTypeSCA,
				Package:     "some-package",
				Description: "Outdated dependency",
			},
			expected: "Outdated dependency",
		},

		// OWASP category handling
		{
			name: "OWASP category with CWE",
			finding: &model.Finding{
				Type: model.FindingTypeVulnerability,
				OWASPCategories: []model.OWASPCategory{
					{ID: "A03:2021", Title: "Injection"},
				},
				CWEs: []string{"CWE-89", "CWE-79"},
			},
			expected: "Injection (CWE-89)",
		},
		{
			name: "OWASP category without CWE",
			finding: &model.Finding{
				Type: model.FindingTypeVulnerability,
				OWASPCategories: []model.OWASPCategory{
					{ID: "A01:2021", Title: "Broken Access Control"},
				},
			},
			expected: "Broken Access Control",
		},
		{
			name: "OWASP category with empty title falls through",
			finding: &model.Finding{
				Type: model.FindingTypeVulnerability,
				OWASPCategories: []model.OWASPCategory{
					{ID: "A03:2021", Title: ""},
				},
				Description: "Some vulnerability description",
			},
			expected: "Some vulnerability description",
		},
		{
			name: "multiple OWASP categories uses first one",
			finding: &model.Finding{
				Type: model.FindingTypeVulnerability,
				OWASPCategories: []model.OWASPCategory{
					{ID: "A03:2021", Title: "Injection"},
					{ID: "A07:2021", Title: "Identification and Authentication Failures"},
				},
				CWEs: []string{"CWE-89"},
			},
			expected: "Injection (CWE-89)",
		},

		// Secret findings
		{
			name: "Secret finding returns fixed string",
			finding: &model.Finding{
				Type:        model.FindingTypeSecret,
				Description: "AWS API key exposed",
			},
			expected: "Exposed Secret",
		},

		// Description fallback
		{
			name: "description fallback - short description",
			finding: &model.Finding{
				Type:        model.FindingTypeVulnerability,
				Description: "SQL Injection vulnerability",
			},
			expected: "SQL Injection vulnerability",
		},
		{
			name: "description fallback - truncated at period",
			finding: &model.Finding{
				Type:        model.FindingTypeVulnerability,
				Description: "SQL Injection vulnerability detected. This allows attackers to execute arbitrary SQL queries.",
			},
			expected: "SQL Injection vulnerability detected",
		},
		{
			name: "description fallback - hard truncation at 77 chars",
			finding: &model.Finding{
				Type:        model.FindingTypeVulnerability,
				Description: "This is a very long description that does not contain a period within the first eighty characters so it will be hard truncated",
			},
			expected: "This is a very long description that does not contain a period within the fir...",
		},
		{
			name: "description fallback - multiline uses first line",
			finding: &model.Finding{
				Type:        model.FindingTypeVulnerability,
				Description: "First line of description\nSecond line with more details\nThird line",
			},
			expected: "First line of description",
		},
		{
			name: "description fallback - period at exactly position 80",
			finding: &model.Finding{
				Type: model.FindingTypeVulnerability,
				// Create a description where ". " appears at exactly position 80
				Description: "This description has a period at exactly the eighty character boundary position. More text follows.",
			},
			expected: "This description has a period at exactly the eighty character boundary position",
		},

		// Category fallback
		{
			name: "category fallback - formats category name",
			finding: &model.Finding{
				Type:            model.FindingTypeVulnerability,
				FindingCategory: "CODE_VULNERABILITY",
			},
			expected: "Code Vulnerability",
		},
		{
			name: "category fallback - single word category",
			finding: &model.Finding{
				Type:            model.FindingTypeVulnerability,
				FindingCategory: "VULNERABILITY",
			},
			expected: "Vulnerability",
		},

		// Default fallback
		{
			name: "default fallback - no info available",
			finding: &model.Finding{
				Type: model.FindingTypeVulnerability,
			},
			expected: "Security Finding",
		},
		{
			name: "default fallback - empty strings",
			finding: &model.Finding{
				Type:            model.FindingTypeVulnerability,
				Description:     "",
				FindingCategory: "",
			},
			expected: "Security Finding",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateFindingTitle(tt.finding)
			if result != tt.expected {
				t.Errorf("generateFindingTitle() = %q, want %q", result, tt.expected)
			}
		})
	}
}
