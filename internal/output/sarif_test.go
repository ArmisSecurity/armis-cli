package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

const testFileMainGo = "main.go"

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
				File:        testFileMainGo,
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

	// Verify rules are generated
	if len(run.Tool.Driver.Rules) != 2 {
		t.Fatalf("Expected 2 rules, got %d", len(run.Tool.Driver.Rules))
	}

	// Verify first rule has security-severity
	rule1 := run.Tool.Driver.Rules[0]
	if rule1.ID != "finding-1" {
		t.Errorf("Rule ID mismatch: got %s, want finding-1", rule1.ID)
	}
	if rule1.Properties == nil {
		t.Fatal("Expected rule properties to be set")
	}
	if rule1.Properties.SecuritySeverity != "8.0" {
		t.Errorf("Security severity mismatch: got %s, want 8.0 (HIGH)", rule1.Properties.SecuritySeverity)
	}

	// Verify second rule (CRITICAL)
	rule2 := run.Tool.Driver.Rules[1]
	if rule2.Properties.SecuritySeverity != "9.5" {
		t.Errorf("Security severity mismatch: got %s, want 9.5 (CRITICAL)", rule2.Properties.SecuritySeverity)
	}

	result1 := run.Results[0]
	if result1.RuleID != "finding-1" {
		t.Errorf("RuleID mismatch: got %s, want finding-1", result1.RuleID)
	}
	if result1.RuleIndex != 0 {
		t.Errorf("RuleIndex mismatch: got %d, want 0", result1.RuleIndex)
	}
	if result1.Level != "error" {
		t.Errorf("Level mismatch: got %s, want error", result1.Level)
	}
	// Verify properties.severity is set
	if result1.Properties == nil {
		t.Fatal("Expected result properties to be set")
	}
	if result1.Properties.Severity != "HIGH" {
		t.Errorf("Severity property mismatch: got %s, want HIGH", result1.Properties.Severity)
	}
	if len(result1.Locations) != 1 {
		t.Fatalf("Expected 1 location, got %d", len(result1.Locations))
	}
	if result1.Locations[0].PhysicalLocation.ArtifactLocation.URI != testFileMainGo {
		t.Errorf("File mismatch: got %s", result1.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}

	// Verify second result
	result2 := run.Results[1]
	if result2.RuleIndex != 1 {
		t.Errorf("RuleIndex mismatch: got %d, want 1", result2.RuleIndex)
	}
	if result2.Properties.Severity != "CRITICAL" {
		t.Errorf("Severity property mismatch: got %s, want CRITICAL", result2.Properties.Severity)
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

func TestSeverityToSecurityScore(t *testing.T) {
	tests := []struct {
		severity model.Severity
		expected string
	}{
		{model.SeverityCritical, "9.5"},
		{model.SeverityHigh, "8.0"},
		{model.SeverityMedium, "5.5"},
		{model.SeverityLow, "2.0"},
		{model.SeverityInfo, "0.0"},
		{model.Severity("UNKNOWN"), "0.0"},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			result := severityToSecurityScore(tt.severity)
			if result != tt.expected {
				t.Errorf("severityToSecurityScore(%s) = %s, want %s", tt.severity, result, tt.expected)
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

func ptr[T any](v T) *T {
	return &v
}

func TestBuildMessageText(t *testing.T) {
	tests := []struct {
		name        string
		title       string
		description string
		expected    string
	}{
		{
			name:        "different title and description",
			title:       "SQL Injection",
			description: "User input directly concatenated into SQL query",
			expected:    "SQL Injection: User input directly concatenated into SQL query",
		},
		{
			name:        "title equals description",
			title:       "SQL Injection vulnerability",
			description: "SQL Injection vulnerability",
			expected:    "SQL Injection vulnerability",
		},
		{
			name:        "empty title",
			title:       "",
			description: "Some vulnerability description",
			expected:    "Some vulnerability description",
		},
		{
			name:        "empty description with title",
			title:       "SQL Injection",
			description: "",
			expected:    "SQL Injection: ",
		},
		{
			name:        "both empty",
			title:       "",
			description: "",
			expected:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildMessageText(tt.title, tt.description)
			if result != tt.expected {
				t.Errorf("buildMessageText(%q, %q) = %q, want %q", tt.title, tt.description, result, tt.expected)
			}
		})
	}
}

func TestSARIFFormatter_WithFixAndValidation(t *testing.T) {
	formatter := &SARIFFormatter{}

	patch := `--- a/main.go
+++ b/main.go
@@ -40,2 +40,2 @@
-    query := "SELECT * FROM users WHERE id = '" + id + "'"
+    query := "SELECT * FROM users WHERE id = ?"`

	result := &model.ScanResult{
		ScanID: "test-scan-with-fix",
		Status: "completed",
		Findings: []model.Finding{
			{
				ID:          "vuln-001",
				Type:        model.FindingTypeVulnerability,
				Severity:    model.SeverityCritical,
				Title:       "SQL Injection",
				Description: "User input directly concatenated into SQL query",
				File:        "main.go",
				StartLine:   42,
				CWEs:        []string{"CWE-89"},
				Fix: &model.Fix{
					IsValid:         true,
					Explanation:     "Use parameterized queries to prevent SQL injection",
					Recommendations: "Replace string concatenation with prepared statements",
					Patch:           &patch,
					Feedback:        "Fix verified as correct",
				},
				Validation: &model.FindingValidation{
					IsValid:           true,
					ValidatedSeverity: ptr("CRITICAL"),
					Confidence:        92,
					Explanation:       "User input flows directly to SQL query",
					TaintPropagation:  model.TaintReachable,
					Exposure:          ptr(6),
				},
			},
			{
				ID:          "vuln-002",
				Type:        model.FindingTypeVulnerability,
				Severity:    model.SeverityMedium,
				Title:       "Weak Hash",
				Description: "MD5 used for password hashing",
				File:        "auth.go",
				StartLine:   15,
				// No fix or validation - should still work
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

	if len(report.Runs[0].Results) != 2 {
		t.Fatalf("Expected 2 results, got %d", len(report.Runs[0].Results))
	}

	// Verify first result has fix and validation
	result1 := report.Runs[0].Results[0]
	if result1.Properties == nil {
		t.Fatal("Expected result properties to be set")
	}

	// Check fix properties
	if result1.Properties.Fix == nil {
		t.Fatal("Expected fix properties to be set for finding with fix")
	}
	if !result1.Properties.Fix.IsValid {
		t.Error("Expected fix.isValid to be true")
	}
	if result1.Properties.Fix.Explanation != "Use parameterized queries to prevent SQL injection" {
		t.Errorf("Fix explanation mismatch: got %s", result1.Properties.Fix.Explanation)
	}
	if result1.Properties.Fix.Recommendations != "Replace string concatenation with prepared statements" {
		t.Errorf("Fix recommendations mismatch: got %s", result1.Properties.Fix.Recommendations)
	}
	if result1.Properties.Fix.Patch == "" {
		t.Error("Expected fix.patch to be set")
	}
	if result1.Properties.Fix.Feedback != "Fix verified as correct" {
		t.Errorf("Fix feedback mismatch: got %s", result1.Properties.Fix.Feedback)
	}

	// Check validation properties
	if result1.Properties.Validation == nil {
		t.Fatal("Expected validation properties to be set for finding with validation")
	}
	if !result1.Properties.Validation.IsValid {
		t.Error("Expected validation.isValid to be true")
	}
	if result1.Properties.Validation.Confidence != 92 {
		t.Errorf("Validation confidence mismatch: got %d, want 92", result1.Properties.Validation.Confidence)
	}
	if result1.Properties.Validation.ValidatedSeverity != "CRITICAL" {
		t.Errorf("Validated severity mismatch: got %s", result1.Properties.Validation.ValidatedSeverity)
	}
	if result1.Properties.Validation.TaintPropagation != "REACHABLE" {
		t.Errorf("Taint propagation mismatch: got %s", result1.Properties.Validation.TaintPropagation)
	}
	if result1.Properties.Validation.Exposure == nil || *result1.Properties.Validation.Exposure != 6 {
		t.Error("Expected exposure to be 6")
	}

	// Verify second result has no fix or validation
	result2 := report.Runs[0].Results[1]
	if result2.Properties.Fix != nil {
		t.Error("Expected no fix properties for finding without fix")
	}
	if result2.Properties.Validation != nil {
		t.Error("Expected no validation properties for finding without validation")
	}
}

func TestSARIFFormatter_StandardFixesArray(t *testing.T) {
	formatter := &SARIFFormatter{}

	startLine := 42
	endLine := 44

	result := &model.ScanResult{
		ScanID: "test-scan-fixes",
		Status: "completed",
		Findings: []model.Finding{
			{
				ID:          "vuln-with-proposed-fix",
				Type:        model.FindingTypeVulnerability,
				Severity:    model.SeverityCritical,
				Title:       "SQL Injection",
				Description: "User input directly concatenated into SQL query",
				File:        "main.go",
				StartLine:   42,
				EndLine:     44,
				Fix: &model.Fix{
					IsValid:     true,
					Explanation: "Use parameterized queries to prevent SQL injection",
					VulnerableCode: &model.CodeSnippetFix{
						FilePath:  "main.go",
						StartLine: &startLine,
						EndLine:   &endLine,
						Content:   `query := "SELECT * FROM users WHERE id = '" + id + "'"`,
					},
					ProposedFixes: []model.CodeSnippetFix{
						{
							FilePath:  "main.go",
							StartLine: &startLine,
							EndLine:   &endLine,
							Content:   `query := "SELECT * FROM users WHERE id = ?"`,
						},
					},
				},
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

	// Verify standard SARIF fixes array is present
	if len(result1.Fixes) == 0 {
		t.Fatal("Expected SARIF fixes array to be populated")
	}

	fix := result1.Fixes[0]

	// Check description
	if fix.Description == nil {
		t.Error("Expected fix description to be set")
	} else if fix.Description.Text != "Use parameterized queries to prevent SQL injection" {
		t.Errorf("Fix description mismatch: got %q", fix.Description.Text)
	}

	// Check artifact changes
	if len(fix.ArtifactChanges) == 0 {
		t.Fatal("Expected artifact changes to be present")
	}

	artifactChange := fix.ArtifactChanges[0]
	if artifactChange.ArtifactLocation.URI != "main.go" {
		t.Errorf("Artifact location mismatch: got %q", artifactChange.ArtifactLocation.URI)
	}

	// Check replacements
	if len(artifactChange.Replacements) == 0 {
		t.Fatal("Expected replacements to be present")
	}

	replacement := artifactChange.Replacements[0]
	if replacement.DeletedRegion.StartLine != 42 {
		t.Errorf("DeletedRegion.StartLine mismatch: got %d, want 42", replacement.DeletedRegion.StartLine)
	}
	if replacement.DeletedRegion.EndLine != 44 {
		t.Errorf("DeletedRegion.EndLine mismatch: got %d, want 44", replacement.DeletedRegion.EndLine)
	}
	if replacement.InsertedContent == nil {
		t.Fatal("Expected InsertedContent to be present")
	}
	if replacement.InsertedContent.Text != `query := "SELECT * FROM users WHERE id = ?"` {
		t.Errorf("InsertedContent mismatch: got %q", replacement.InsertedContent.Text)
	}

	// Verify custom properties fix is also present (backward compatibility)
	if result1.Properties.Fix == nil {
		t.Error("Expected custom properties fix to also be present for backward compatibility")
	}
}

func TestSARIFFormatter_FixesArrayWithPatchFiles(t *testing.T) {
	formatter := &SARIFFormatter{}

	result := &model.ScanResult{
		ScanID: "test-scan-patch-files",
		Status: "completed",
		Findings: []model.Finding{
			{
				ID:          "vuln-with-patch-files",
				Type:        model.FindingTypeVulnerability,
				Severity:    model.SeverityHigh,
				Title:       "XSS Vulnerability",
				Description: "Unescaped output",
				File:        "template.html",
				StartLine:   10,
				EndLine:     12,
				Fix: &model.Fix{
					IsValid:     true,
					Explanation: "Escape HTML output",
					PatchFiles: map[string]string{
						"template.html": "<div>{{ .UserInput | html }}</div>",
					},
				},
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

	result1 := report.Runs[0].Results[0]

	// Verify fixes array is populated from PatchFiles
	if len(result1.Fixes) == 0 {
		t.Fatal("Expected SARIF fixes array to be populated from PatchFiles")
	}

	fix := result1.Fixes[0]
	if len(fix.ArtifactChanges) == 0 {
		t.Fatal("Expected artifact changes")
	}

	artifactChange := fix.ArtifactChanges[0]
	if artifactChange.ArtifactLocation.URI != "template.html" {
		t.Errorf("Expected template.html, got %s", artifactChange.ArtifactLocation.URI)
	}

	if len(artifactChange.Replacements) == 0 {
		t.Fatal("Expected replacements")
	}

	if artifactChange.Replacements[0].InsertedContent.Text != "<div>{{ .UserInput | html }}</div>" {
		t.Errorf("InsertedContent mismatch: got %q", artifactChange.Replacements[0].InsertedContent.Text)
	}
}

func TestSARIFFormatter_NoFixesArrayWithoutFix(t *testing.T) {
	formatter := &SARIFFormatter{}

	result := &model.ScanResult{
		ScanID: "test-scan-no-fix",
		Status: "completed",
		Findings: []model.Finding{
			{
				ID:          "vuln-no-fix",
				Type:        model.FindingTypeVulnerability,
				Severity:    model.SeverityMedium,
				Title:       "Some Vulnerability",
				Description: "No fix available",
				File:        "main.go",
				StartLine:   10,
				// No Fix field
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

	result1 := report.Runs[0].Results[0]

	// Verify no fixes array when no fix data
	if len(result1.Fixes) != 0 {
		t.Errorf("Expected no fixes array, got %d fixes", len(result1.Fixes))
	}
}

func TestConvertFixToSarif(t *testing.T) {
	startLine := 10
	endLine := 15

	tests := []struct {
		name          string
		finding       model.Finding
		expectedFixes int
		checkFirstFix func(t *testing.T, fix sarifFix)
	}{
		{
			name: "nil fix returns nil",
			finding: model.Finding{
				ID:  "test-1",
				Fix: nil,
			},
			expectedFixes: 0,
		},
		{
			name: "empty fix returns nil",
			finding: model.Finding{
				ID:  "test-2",
				Fix: &model.Fix{},
			},
			expectedFixes: 0,
		},
		{
			name: "proposed fixes without vulnerable code returns empty",
			finding: model.Finding{
				ID: "test-3",
				Fix: &model.Fix{
					ProposedFixes: []model.CodeSnippetFix{
						{Content: "fixed code"},
					},
					// VulnerableCode is nil
				},
			},
			expectedFixes: 0,
		},
		{
			name: "proposed fixes with vulnerable code",
			finding: model.Finding{
				ID:   "test-4",
				File: "main.go",
				Fix: &model.Fix{
					Explanation: "Fix explanation",
					VulnerableCode: &model.CodeSnippetFix{
						FilePath:  "main.go",
						StartLine: &startLine,
						EndLine:   &endLine,
					},
					ProposedFixes: []model.CodeSnippetFix{
						{
							FilePath: "main.go",
							Content:  "fixed code",
						},
					},
				},
			},
			expectedFixes: 1,
			checkFirstFix: func(t *testing.T, fix sarifFix) {
				if fix.Description == nil || fix.Description.Text != "Fix explanation" {
					t.Error("Expected description to be set")
				}
				if len(fix.ArtifactChanges) != 1 {
					t.Fatalf("Expected 1 artifact change, got %d", len(fix.ArtifactChanges))
				}
				if fix.ArtifactChanges[0].ArtifactLocation.URI != "main.go" {
					t.Errorf("Expected main.go, got %s", fix.ArtifactChanges[0].ArtifactLocation.URI)
				}
			},
		},
		{
			name: "patch files creates fixes",
			finding: model.Finding{
				ID:        "test-5",
				File:      "config.go",
				StartLine: 5,
				EndLine:   8,
				Fix: &model.Fix{
					Explanation: "Update config",
					PatchFiles: map[string]string{
						"config.go": "new config content",
					},
				},
			},
			expectedFixes: 1,
			checkFirstFix: func(t *testing.T, fix sarifFix) {
				if len(fix.ArtifactChanges) != 1 {
					t.Fatalf("Expected 1 artifact change, got %d", len(fix.ArtifactChanges))
				}
				if fix.ArtifactChanges[0].Replacements[0].InsertedContent.Text != "new config content" {
					t.Error("InsertedContent mismatch")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixes := convertFixToSarif(tt.finding)
			if len(fixes) != tt.expectedFixes {
				t.Errorf("Expected %d fixes, got %d", tt.expectedFixes, len(fixes))
			}
			if tt.checkFirstFix != nil && len(fixes) > 0 {
				tt.checkFirstFix(t, fixes[0])
			}
		})
	}
}

func TestGenerateHelpURI(t *testing.T) {
	tests := []struct {
		name     string
		finding  model.Finding
		expected string
	}{
		{
			name:     "CVE takes priority",
			finding:  model.Finding{CVEs: []string{"CVE-2023-1234"}, CWEs: []string{"CWE-89"}},
			expected: "https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
		},
		{
			name:     "uppercase CWE prefix",
			finding:  model.Finding{CWEs: []string{"CWE-89"}},
			expected: "https://cwe.mitre.org/data/definitions/89.html",
		},
		{
			name:     "lowercase cwe prefix",
			finding:  model.Finding{CWEs: []string{"cwe-123"}},
			expected: "https://cwe.mitre.org/data/definitions/123.html",
		},
		{
			name:     "CWE without prefix",
			finding:  model.Finding{CWEs: []string{"456"}},
			expected: "https://cwe.mitre.org/data/definitions/456.html",
		},
		{
			name:     "mixed case CWE prefix",
			finding:  model.Finding{CWEs: []string{"Cwe-789"}},
			expected: "https://cwe.mitre.org/data/definitions/789.html",
		},
		{
			name:     "URL fallback",
			finding:  model.Finding{URLs: []string{"https://example.com/security"}},
			expected: "https://example.com/security",
		},
		{
			name:     "empty finding returns empty",
			finding:  model.Finding{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateHelpURI(tt.finding)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestConvertFixToSarif_ProposedFixesPriority(t *testing.T) {
	startLine := 10
	endLine := 15

	// When both ProposedFixes and PatchFiles exist, ProposedFixes should take priority
	finding := model.Finding{
		ID:        "test-priority",
		File:      "main.go",
		StartLine: 5,
		EndLine:   8,
		Fix: &model.Fix{
			Explanation: "Fix via proposed fix",
			VulnerableCode: &model.CodeSnippetFix{
				FilePath:  "main.go",
				StartLine: &startLine,
				EndLine:   &endLine,
			},
			ProposedFixes: []model.CodeSnippetFix{
				{
					FilePath: "main.go",
					Content:  "proposed fix content",
				},
			},
			PatchFiles: map[string]string{
				"main.go": "patch file content",
			},
		},
	}

	fixes := convertFixToSarif(finding)

	// Should only have 1 fix (from ProposedFixes), not 2
	if len(fixes) != 1 {
		t.Fatalf("Expected 1 fix (ProposedFixes should take priority), got %d", len(fixes))
	}

	// Verify it's the ProposedFix, not the PatchFile
	if fixes[0].ArtifactChanges[0].Replacements[0].InsertedContent.Text != "proposed fix content" {
		t.Errorf("Expected proposed fix content, got %q", fixes[0].ArtifactChanges[0].Replacements[0].InsertedContent.Text)
	}
}
