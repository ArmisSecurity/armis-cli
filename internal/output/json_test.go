package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

func TestJSONFormatter_Format(t *testing.T) {
	formatter := &JSONFormatter{}

	result := &model.ScanResult{
		ScanID: "test-scan-123",
		Status: "completed",
		Findings: []model.Finding{
			{
				ID:          "finding-1",
				Type:        model.FindingTypeVulnerability,
				Severity:    model.SeverityHigh,
				Title:       "SQL Injection",
				Description: "Potential SQL injection vulnerability",
				File:        "main.go",
				StartLine:   42,
				EndLine:     45,
				CVEs:        []string{"CVE-2023-1234"},
				CWEs:        []string{"CWE-89"},
			},
		},
		Summary: model.Summary{
			Total: 1,
			BySeverity: map[model.Severity]int{
				model.SeverityHigh: 1,
			},
			ByType: map[model.FindingType]int{
				model.FindingTypeVulnerability: 1,
			},
		},
	}

	var buf bytes.Buffer
	err := formatter.Format(result, &buf)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	var decoded model.ScanResult
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("Failed to decode JSON: %v", err)
	}

	if decoded.ScanID != result.ScanID {
		t.Errorf("ScanID mismatch: got %s, want %s", decoded.ScanID, result.ScanID)
	}
	if len(decoded.Findings) != len(result.Findings) {
		t.Errorf("Findings count mismatch: got %d, want %d", len(decoded.Findings), len(result.Findings))
	}
	if decoded.Findings[0].Title != result.Findings[0].Title {
		t.Errorf("Finding title mismatch: got %s, want %s", decoded.Findings[0].Title, result.Findings[0].Title)
	}
}

func TestJSONFormatter_FormatWithOptions(t *testing.T) {
	formatter := &JSONFormatter{}

	result := &model.ScanResult{
		ScanID:   "test-scan",
		Status:   "completed",
		Findings: []model.Finding{},
		Summary: model.Summary{
			Total: 0,
		},
	}

	var buf bytes.Buffer
	opts := FormatOptions{
		GroupBy:  "severity",
		RepoPath: "/tmp/test",
	}

	err := formatter.FormatWithOptions(result, &buf, opts)
	if err != nil {
		t.Fatalf("FormatWithOptions failed: %v", err)
	}

	var decoded model.ScanResult
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("Failed to decode JSON: %v", err)
	}

	if decoded.ScanID != result.ScanID {
		t.Errorf("ScanID mismatch: got %s, want %s", decoded.ScanID, result.ScanID)
	}
}

func TestJSONFormatter_EmptyFindings(t *testing.T) {
	formatter := &JSONFormatter{}

	result := &model.ScanResult{
		ScanID:   "empty-scan",
		Status:   "completed",
		Findings: []model.Finding{},
		Summary: model.Summary{
			Total:      0,
			BySeverity: map[model.Severity]int{},
			ByType:     map[model.FindingType]int{},
		},
	}

	var buf bytes.Buffer
	err := formatter.Format(result, &buf)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	var decoded model.ScanResult
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("Failed to decode JSON: %v", err)
	}

	if len(decoded.Findings) != 0 {
		t.Errorf("Expected 0 findings, got %d", len(decoded.Findings))
	}
}
