package model

import (
	"encoding/json"
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
