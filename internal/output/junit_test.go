package output

import (
	"bytes"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

func TestJUnitFormatter_Format(t *testing.T) {
	formatter := &JUnitFormatter{}

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
			},
			{
				ID:          "finding-2",
				Type:        model.FindingTypeSecret,
				Severity:    model.SeverityMedium,
				Title:       "Weak Password",
				Description: "Password complexity insufficient",
			},
		},
	}

	var buf bytes.Buffer
	err := formatter.Format(result, &buf)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "<?xml version") {
		t.Error("Expected XML header")
	}

	var suites junitTestSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("Failed to decode JUnit XML: %v", err)
	}

	if len(suites.Suites) != 1 {
		t.Fatalf("Expected 1 test suite, got %d", len(suites.Suites))
	}

	suite := suites.Suites[0]
	if suite.Tests != 2 {
		t.Errorf("Expected 2 tests, got %d", suite.Tests)
	}
	if suite.Failures != 1 {
		t.Errorf("Expected 1 failure (HIGH severity), got %d", suite.Failures)
	}

	if len(suite.Cases) != 2 {
		t.Fatalf("Expected 2 test cases, got %d", len(suite.Cases))
	}

	case1 := suite.Cases[0]
	if case1.Name != "SQL Injection" {
		t.Errorf("Case name mismatch: got %s", case1.Name)
	}
	if case1.Failure == nil {
		t.Error("Expected failure for HIGH severity finding")
	}
	if case1.Failure.Type != "HIGH" {
		t.Errorf("Failure type mismatch: got %s, want HIGH", case1.Failure.Type)
	}

	case2 := suite.Cases[1]
	if case2.Failure != nil {
		t.Error("Expected no failure for MEDIUM severity finding")
	}
}

func TestCountFailures(t *testing.T) {
	tests := []struct {
		name     string
		findings []model.Finding
		expected int
	}{
		{
			name:     "no findings",
			findings: []model.Finding{},
			expected: 0,
		},
		{
			name: "only critical and high",
			findings: []model.Finding{
				{Severity: model.SeverityCritical},
				{Severity: model.SeverityHigh},
				{Severity: model.SeverityHigh},
			},
			expected: 3,
		},
		{
			name: "mixed severities",
			findings: []model.Finding{
				{Severity: model.SeverityCritical},
				{Severity: model.SeverityMedium},
				{Severity: model.SeverityLow},
				{Severity: model.SeverityInfo},
			},
			expected: 1,
		},
		{
			name: "no high severity",
			findings: []model.Finding{
				{Severity: model.SeverityMedium},
				{Severity: model.SeverityLow},
			},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := countFailures(tt.findings)
			if result != tt.expected {
				t.Errorf("countFailures() = %d, want %d", result, tt.expected)
			}
		})
	}
}

func TestConvertToJUnitCases(t *testing.T) {
	findings := []model.Finding{
		{
			ID:          "1",
			Type:        model.FindingTypeVulnerability,
			Severity:    model.SeverityCritical,
			Title:       "Critical Issue",
			Description: "Very bad",
			File:        "test.go",
			StartLine:   10,
		},
		{
			ID:       "2",
			Type:     model.FindingTypeSecret,
			Severity: model.SeverityLow,
			Title:    "Low Issue",
		},
	}

	cases := convertToJUnitCases(findings)

	if len(cases) != 2 {
		t.Fatalf("Expected 2 cases, got %d", len(cases))
	}

	if cases[0].Name != "Critical Issue" {
		t.Errorf("Case name mismatch: got %s", cases[0].Name)
	}
	if cases[0].Classname != "VULNERABILITY" {
		t.Errorf("Classname mismatch: got %s", cases[0].Classname)
	}
	if cases[0].Failure == nil {
		t.Error("Expected failure for CRITICAL severity")
	}
	if !strings.Contains(cases[0].Failure.Content, "test.go:10") {
		t.Errorf("Expected location in failure content, got: %s", cases[0].Failure.Content)
	}

	if cases[1].Failure != nil {
		t.Error("Expected no failure for LOW severity")
	}
}

func TestJUnitFormatter_FormatWithOptions(t *testing.T) {
	formatter := &JUnitFormatter{}

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

	var suites junitTestSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("Failed to decode JUnit XML: %v", err)
	}

	if len(suites.Suites) != 1 {
		t.Fatalf("Expected 1 test suite, got %d", len(suites.Suites))
	}
}
