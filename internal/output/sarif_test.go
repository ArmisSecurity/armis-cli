package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

func TestSARIFFormatter_Format(t *testing.T) {
	formatter := &SARIFFormatter{}

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
				StartColumn: 10,
			},
			{
				ID:          "finding-2",
				Type:        model.FindingTypeSecret,
				Severity:    model.SeverityCritical,
				Title:       "Exposed API Key",
				Description: "API key found in code",
				File:        "config.go",
				StartLine:   15,
			},
		},
	}

	var buf bytes.Buffer
	err := formatter.Format(result, &buf)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	var report sarifReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("Failed to decode SARIF: %v", err)
	}

	if report.Version != "2.1.0" {
		t.Errorf("Version mismatch: got %s, want 2.1.0", report.Version)
	}

	if len(report.Runs) != 1 {
		t.Fatalf("Expected 1 run, got %d", len(report.Runs))
	}

	run := report.Runs[0]
	if run.Tool.Driver.Name != "Armis Security Scanner" {
		t.Errorf("Tool name mismatch: got %s", run.Tool.Driver.Name)
	}

	if len(run.Results) != 2 {
		t.Fatalf("Expected 2 results, got %d", len(run.Results))
	}

	result1 := run.Results[0]
	if result1.RuleID != "finding-1" {
		t.Errorf("RuleID mismatch: got %s, want finding-1", result1.RuleID)
	}
	if result1.Level != "error" {
		t.Errorf("Level mismatch: got %s, want error", result1.Level)
	}
	if len(result1.Locations) != 1 {
		t.Fatalf("Expected 1 location, got %d", len(result1.Locations))
	}
	if result1.Locations[0].PhysicalLocation.ArtifactLocation.URI != "main.go" {
		t.Errorf("File mismatch: got %s", result1.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
}

func TestSeverityToSarifLevel(t *testing.T) {
	tests := []struct {
		severity model.Severity
		expected string
	}{
		{model.SeverityCritical, "error"},
		{model.SeverityHigh, "error"},
		{model.SeverityMedium, "warning"},
		{model.SeverityLow, "note"},
		{model.SeverityInfo, "note"},
		{model.Severity("UNKNOWN"), "none"},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			result := severityToSarifLevel(tt.severity)
			if result != tt.expected {
				t.Errorf("severityToSarifLevel(%s) = %s, want %s", tt.severity, result, tt.expected)
			}
		})
	}
}

func TestSARIFFormatter_NoLocation(t *testing.T) {
	formatter := &SARIFFormatter{}

	result := &model.ScanResult{
		ScanID: "test-scan",
		Findings: []model.Finding{
			{
				ID:          "finding-1",
				Type:        model.FindingTypeSCA,
				Severity:    model.SeverityMedium,
				Title:       "Outdated Dependency",
				Description: "Package needs update",
			},
		},
	}

	var buf bytes.Buffer
	err := formatter.Format(result, &buf)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	var report sarifReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("Failed to decode SARIF: %v", err)
	}

	if len(report.Runs[0].Results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(report.Runs[0].Results))
	}

	result1 := report.Runs[0].Results[0]
	if len(result1.Locations) != 0 {
		t.Errorf("Expected no locations for finding without file, got %d", len(result1.Locations))
	}
}

func TestSARIFFormatter_FormatWithOptions(t *testing.T) {
	formatter := &SARIFFormatter{}

	result := &model.ScanResult{
		ScanID:   "test-scan",
		Findings: []model.Finding{},
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

	var report sarifReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("Failed to decode SARIF: %v", err)
	}

	if len(report.Runs[0].Results) != 0 {
		t.Errorf("Expected 0 results, got %d", len(report.Runs[0].Results))
	}
}
