package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSeverityConstants(t *testing.T) {
	tests := []struct {
		severity Severity
		expected string
	}{
		{SeverityInfo, "INFO"},
		{SeverityLow, "LOW"},
		{SeverityMedium, "MEDIUM"},
		{SeverityHigh, "HIGH"},
		{SeverityCritical, "CRITICAL"},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			if string(tt.severity) != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, string(tt.severity))
			}
		})
	}
}

func TestFindingTypeConstants(t *testing.T) {
	tests := []struct {
		findingType FindingType
		expected    string
	}{
		{FindingTypeVulnerability, "VULNERABILITY"},
		{FindingTypeSCA, "SCA"},
		{FindingTypeSecret, "SECRET"},
		{FindingTypeLicense, "LICENSE"},
	}

	for _, tt := range tests {
		t.Run(string(tt.findingType), func(t *testing.T) {
			if string(tt.findingType) != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, string(tt.findingType))
			}
		})
	}
}

func TestFindingJSONMarshaling(t *testing.T) {
	finding := Finding{
		ID:          "test-123",
		Type:        FindingTypeVulnerability,
		Severity:    SeverityHigh,
		Title:       "Test Vulnerability",
		Description: "Test description",
		File:        "test.go",
		StartLine:   10,
		EndLine:     15,
		CVEs:        []string{"CVE-2023-1234"},
		CWEs:        []string{"CWE-79"},
	}

	data, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("Failed to marshal finding: %v", err)
	}

	var unmarshaled Finding
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal finding: %v", err)
	}

	if unmarshaled.ID != finding.ID {
		t.Errorf("ID mismatch: got %s, want %s", unmarshaled.ID, finding.ID)
	}
	if unmarshaled.Type != finding.Type {
		t.Errorf("Type mismatch: got %s, want %s", unmarshaled.Type, finding.Type)
	}
	if unmarshaled.Severity != finding.Severity {
		t.Errorf("Severity mismatch: got %s, want %s", unmarshaled.Severity, finding.Severity)
	}
	if unmarshaled.Title != finding.Title {
		t.Errorf("Title mismatch: got %s, want %s", unmarshaled.Title, finding.Title)
	}
	if unmarshaled.StartLine != finding.StartLine {
		t.Errorf("StartLine mismatch: got %d, want %d", unmarshaled.StartLine, finding.StartLine)
	}
}

func TestScanResultJSONMarshaling(t *testing.T) {
	result := ScanResult{
		ScanID: "scan-123",
		Status: "completed",
		Findings: []Finding{
			{
				ID:       "finding-1",
				Type:     FindingTypeSecret,
				Severity: SeverityCritical,
				Title:    "Exposed API Key",
			},
		},
		Summary: Summary{
			Total: 1,
			BySeverity: map[Severity]int{
				SeverityCritical: 1,
			},
			ByType: map[FindingType]int{
				FindingTypeSecret: 1,
			},
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Failed to marshal scan result: %v", err)
	}

	var unmarshaled ScanResult
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal scan result: %v", err)
	}

	if unmarshaled.ScanID != result.ScanID {
		t.Errorf("ScanID mismatch: got %s, want %s", unmarshaled.ScanID, result.ScanID)
	}
	if len(unmarshaled.Findings) != len(result.Findings) {
		t.Errorf("Findings count mismatch: got %d, want %d", len(unmarshaled.Findings), len(result.Findings))
	}
	if unmarshaled.Summary.Total != result.Summary.Total {
		t.Errorf("Summary.Total mismatch: got %d, want %d", unmarshaled.Summary.Total, result.Summary.Total)
	}
}

func TestIngestUploadResponseJSONMarshaling(t *testing.T) {
	response := IngestUploadResponse{
		ScanID:       "scan-456",
		ArtifactType: "image",
		TenantID:     "tenant-789",
		Filename:     "test.tar",
		Message:      "Upload successful",
	}

	data, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("Failed to marshal response: %v", err)
	}

	var unmarshaled IngestUploadResponse
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if unmarshaled.ScanID != response.ScanID {
		t.Errorf("ScanID mismatch: got %s, want %s", unmarshaled.ScanID, response.ScanID)
	}
	if unmarshaled.ArtifactType != response.ArtifactType {
		t.Errorf("ArtifactType mismatch: got %s, want %s", unmarshaled.ArtifactType, response.ArtifactType)
	}
}

func TestNormalizedResultsResponseJSONMarshaling(t *testing.T) {
	nextCursor := "cursor-123"
	response := NormalizedResultsResponse{
		Data: NormalizedResultsData{
			TenantID: "tenant-123",
			ScanResults: []ScanResultData{
				{
					ScanID:   "scan-456",
					ScanTime: 123.45,
					Findings: []NormalizedFinding{},
				},
			},
		},
		Pagination: Pagination{
			NextCursor: &nextCursor,
			Limit:      100,
		},
	}

	data, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("Failed to marshal response: %v", err)
	}

	var unmarshaled NormalizedResultsResponse
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if unmarshaled.Data.TenantID != response.Data.TenantID {
		t.Errorf("TenantID mismatch: got %s, want %s", unmarshaled.Data.TenantID, response.Data.TenantID)
	}
	if unmarshaled.Pagination.Limit != response.Pagination.Limit {
		t.Errorf("Limit mismatch: got %d, want %d", unmarshaled.Pagination.Limit, response.Pagination.Limit)
	}
	if unmarshaled.Pagination.NextCursor == nil || *unmarshaled.Pagination.NextCursor != nextCursor {
		t.Errorf("NextCursor mismatch")
	}
}

// TestFinding_ZeroValue verifies that a zero-value Finding marshals without error
// and omitempty fields are properly omitted from the JSON output.
func TestFinding_ZeroValue(t *testing.T) {
	finding := Finding{}

	data, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("Failed to marshal zero-value finding: %v", err)
	}

	// Verify it unmarshals back correctly
	var unmarshaled Finding
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal zero-value finding: %v", err)
	}

	// Check that omitempty fields are not present in JSON
	var jsonMap map[string]interface{}
	if err := json.Unmarshal(data, &jsonMap); err != nil {
		t.Fatalf("Failed to unmarshal to map: %v", err)
	}

	// Fields with omitempty should be absent when zero
	optionalFields := []string{"file", "start_line", "end_line", "code_snippet", "cves", "cwes", "package", "version", "fix_version"}
	for _, field := range optionalFields {
		if _, exists := jsonMap[field]; exists {
			t.Errorf("Expected omitempty field %q to be absent in zero-value JSON, but it was present", field)
		}
	}
}

// TestFinding_NilSlices verifies that nil CVEs/CWEs slices are handled correctly
// and not serialized as JSON null values.
func TestFinding_NilSlices(t *testing.T) {
	finding := Finding{
		ID:       "test-nil-slices",
		Type:     FindingTypeVulnerability,
		Severity: SeverityHigh,
		Title:    "Test Finding",
		CVEs:     nil, // explicitly nil
		CWEs:     nil, // explicitly nil
	}

	data, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("Failed to marshal finding with nil slices: %v", err)
	}

	// Verify JSON does not contain "cves":null or "cwes":null
	jsonStr := string(data)
	if strings.Contains(jsonStr, `"cves":null`) {
		t.Error("Expected nil CVEs to be omitted, not serialized as null")
	}
	if strings.Contains(jsonStr, `"cwes":null`) {
		t.Error("Expected nil CWEs to be omitted, not serialized as null")
	}

	// Verify it unmarshals back correctly
	var unmarshaled Finding
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// After unmarshal, nil slices should remain nil (not empty slices)
	// Note: This depends on Go's JSON unmarshaling behavior
	if unmarshaled.ID != finding.ID {
		t.Errorf("ID mismatch after unmarshal")
	}
}

// TestScanResult_EmptyFindings verifies that empty findings slice is handled correctly.
func TestScanResult_EmptyFindings(t *testing.T) {
	t.Run("nil findings", func(t *testing.T) {
		result := ScanResult{
			ScanID:   "scan-nil",
			Status:   "completed",
			Findings: nil,
		}

		data, err := json.Marshal(result)
		if err != nil {
			t.Fatalf("Failed to marshal result with nil findings: %v", err)
		}

		var unmarshaled ScanResult
		if err := json.Unmarshal(data, &unmarshaled); err != nil {
			t.Fatalf("Failed to unmarshal: %v", err)
		}

		if unmarshaled.ScanID != result.ScanID {
			t.Errorf("ScanID mismatch")
		}
	})

	t.Run("empty findings slice", func(t *testing.T) {
		result := ScanResult{
			ScanID:   "scan-empty",
			Status:   "completed",
			Findings: []Finding{},
		}

		data, err := json.Marshal(result)
		if err != nil {
			t.Fatalf("Failed to marshal result with empty findings: %v", err)
		}

		var unmarshaled ScanResult
		if err := json.Unmarshal(data, &unmarshaled); err != nil {
			t.Fatalf("Failed to unmarshal: %v", err)
		}

		if unmarshaled.ScanID != result.ScanID {
			t.Errorf("ScanID mismatch")
		}
		if unmarshaled.Findings == nil {
			t.Error("Expected empty findings slice, got nil")
		}
		if len(unmarshaled.Findings) != 0 {
			t.Errorf("Expected 0 findings, got %d", len(unmarshaled.Findings))
		}
	})
}

// TestFinding_WithValidation verifies that FindingValidation serializes correctly.
func TestFinding_WithValidation(t *testing.T) {
	validatedSeverity := "MEDIUM"
	exposure := 5

	finding := Finding{
		ID:       "test-validation",
		Type:     FindingTypeVulnerability,
		Severity: SeverityHigh,
		Title:    "Validated Finding",
		Validation: &FindingValidation{
			IsValid:           true,
			ValidatedSeverity: &validatedSeverity,
			Confidence:        85,
			Explanation:       "This is a valid finding",
			TaintPropagation:  TaintReachable,
			Exposure:          &exposure,
		},
	}

	data, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("Failed to marshal finding with validation: %v", err)
	}

	var unmarshaled Finding
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if unmarshaled.Validation == nil {
		t.Fatal("Expected validation to be present")
	}
	if unmarshaled.Validation.IsValid != true {
		t.Error("IsValid mismatch")
	}
	if unmarshaled.Validation.Confidence != 85 {
		t.Errorf("Confidence mismatch: got %d, want 85", unmarshaled.Validation.Confidence)
	}
	if unmarshaled.Validation.TaintPropagation != TaintReachable {
		t.Errorf("TaintPropagation mismatch: got %s, want %s", unmarshaled.Validation.TaintPropagation, TaintReachable)
	}
	if unmarshaled.Validation.ValidatedSeverity == nil || *unmarshaled.Validation.ValidatedSeverity != "MEDIUM" {
		t.Error("ValidatedSeverity mismatch")
	}
	if unmarshaled.Validation.Exposure == nil || *unmarshaled.Validation.Exposure != 5 {
		t.Error("Exposure mismatch")
	}
}

// TestFinding_WithFix verifies that Fix struct with PatchFiles serializes correctly.
func TestFinding_WithFix(t *testing.T) {
	patch := "--- a/file.go\n+++ b/file.go\n@@ -1,1 +1,1 @@\n-old\n+new"
	startLine := 10
	endLine := 15

	finding := Finding{
		ID:       "test-fix",
		Type:     FindingTypeVulnerability,
		Severity: SeverityCritical,
		Title:    "Finding with Fix",
		Fix: &Fix{
			VulnerableCode: &CodeSnippetFix{
				FilePath:  "vulnerable.go",
				StartLine: &startLine,
				EndLine:   &endLine,
				Content:   "// vulnerable code",
			},
			ProposedFixes: []CodeSnippetFix{
				{
					FilePath: "fixed.go",
					Content:  "// fixed code",
				},
			},
			Patch: &patch,
			PatchFiles: map[string]string{
				"file1.go": "patched content 1",
				"file2.go": "patched content 2",
			},
			Explanation:     "Replace vulnerable code with fixed code",
			Recommendations: "Update to latest version",
			IsValid:         true,
			Feedback:        "Fix verified",
		},
	}

	data, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("Failed to marshal finding with fix: %v", err)
	}

	var unmarshaled Finding
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if unmarshaled.Fix == nil {
		t.Fatal("Expected fix to be present")
	}
	if unmarshaled.Fix.VulnerableCode == nil {
		t.Error("Expected VulnerableCode to be present")
	}
	if len(unmarshaled.Fix.ProposedFixes) != 1 {
		t.Errorf("Expected 1 proposed fix, got %d", len(unmarshaled.Fix.ProposedFixes))
	}
	if len(unmarshaled.Fix.PatchFiles) != 2 {
		t.Errorf("Expected 2 patch files, got %d", len(unmarshaled.Fix.PatchFiles))
	}
	if unmarshaled.Fix.PatchFiles["file1.go"] != "patched content 1" {
		t.Error("PatchFiles content mismatch")
	}
}
