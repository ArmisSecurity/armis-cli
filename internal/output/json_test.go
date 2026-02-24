package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

func TestJSONFormatter_Format(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

func TestJSONFormatter_MasksSecrets(t *testing.T) {
	t.Parallel()
	formatter := &JSONFormatter{}
	secretSnippet := `password = "SuperSecretPassword123!"`

	result := &model.ScanResult{
		ScanID: "test-mask",
		Status: "completed",
		Findings: []model.Finding{
			{
				ID:          "secret-1",
				Type:        model.FindingTypeSecret,
				Severity:    model.SeverityCritical,
				Title:       "Exposed Secret",
				CodeSnippet: secretSnippet,
			},
		},
		Summary: model.Summary{Total: 1},
	}

	var buf bytes.Buffer
	err := formatter.Format(result, &buf)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	output := buf.String()
	if strings.Contains(output, "SuperSecretPassword123!") {
		t.Error("expected secret to be masked in JSON output")
	}
	if !strings.Contains(output, "********") {
		t.Error("expected masked placeholder in JSON output")
	}

	// Verify original struct is not modified
	if result.Findings[0].CodeSnippet != secretSnippet {
		t.Error("original ScanResult should not be modified by formatter")
	}
}

func TestJSONFormatter_MasksFixSecrets(t *testing.T) {
	t.Parallel()
	formatter := &JSONFormatter{}
	secretPatch := `- password = "OldSecret123"
+ password = "NewSecret456"` // #nosec G101 - test data for secret masking

	patch := secretPatch
	result := &model.ScanResult{
		ScanID: "test-fix-mask",
		Status: "completed",
		Findings: []model.Finding{
			{
				ID:       "fix-secret-1",
				Type:     model.FindingTypeSecret,
				Severity: model.SeverityHigh,
				Title:    "Secret with Fix",
				Fix: &model.Fix{
					Patch:       &patch,
					Explanation: "Remove hardcoded password",
				},
			},
		},
		Summary: model.Summary{Total: 1},
	}

	var buf bytes.Buffer
	err := formatter.Format(result, &buf)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	output := buf.String()
	if strings.Contains(output, "OldSecret123") || strings.Contains(output, "NewSecret456") {
		t.Error("expected secrets in Fix.Patch to be masked in JSON output")
	}
}

func TestJSONFormatter_MaskedContentPreserved(t *testing.T) {
	t.Parallel()
	formatter := &JSONFormatter{}
	// Already masked content - masking preserves the masked markers
	alreadyMasked := `password = ********[20-40]`

	result := &model.ScanResult{
		ScanID: "test-masked",
		Status: "completed",
		Findings: []model.Finding{
			{
				ID:          "masked-1",
				Type:        model.FindingTypeSecret,
				Severity:    model.SeverityMedium,
				Title:       "Already Masked",
				CodeSnippet: alreadyMasked,
			},
		},
		Summary: model.Summary{Total: 1},
	}

	var buf bytes.Buffer
	err := formatter.Format(result, &buf)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Should still contain masked markers (may be re-masked but not corrupted)
	output := buf.String()
	if !strings.Contains(output, "********") {
		t.Error("masked content should be preserved with masked markers")
	}
	// Should not contain raw secret values
	if strings.Contains(output, "SuperSecret") || strings.Contains(output, "password123") {
		t.Error("should not contain any raw secrets")
	}
}

func TestJSONFormatter_MasksAllFixFields(t *testing.T) {
	t.Parallel()
	formatter := &JSONFormatter{}

	startLine := 10
	endLine := 15
	result := &model.ScanResult{
		ScanID: "test-all-fix-fields",
		Status: "completed",
		Findings: []model.Finding{
			{
				ID:       "fix-all-1",
				Type:     model.FindingTypeSecret,
				Severity: model.SeverityHigh,
				Title:    "Secret with all fix fields",
				Fix: &model.Fix{
					VulnerableCode: &model.CodeSnippetFix{
						Content: `api_key = "sk-vulnerable-key-12345"`, // #nosec G101
					},
					ProposedFixes: []model.CodeSnippetFix{
						{
							FilePath:  "config.go",
							StartLine: &startLine,
							EndLine:   &endLine,
							Content:   `secret_key = "sk-proposed-fix-secret-value"`, // #nosec G101
						},
					},
					PatchFiles: map[string]string{
						"config.go": `- api_key = "sk-patchfile-secret-789"`, // #nosec G101
					},
				},
			},
		},
		Summary: model.Summary{Total: 1},
	}

	var buf bytes.Buffer
	err := formatter.Format(result, &buf)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	output := buf.String()

	// Verify all secret values are masked
	secrets := []string{
		"sk-vulnerable-key-12345",
		"sk-proposed-fix-secret-value",
		"sk-patchfile-secret-789",
	}
	for _, secret := range secrets {
		if strings.Contains(output, secret) {
			t.Errorf("expected %q to be masked in JSON output", secret)
		}
	}

	// Verify masked placeholders are present
	if !strings.Contains(output, "********") {
		t.Error("expected masked placeholders in JSON output")
	}
}

func TestJSONFormatter_MultiLineSecrets(t *testing.T) {
	t.Parallel()
	formatter := &JSONFormatter{}
	multiLineSnippet := `config := struct {
    Password string
    APIKey   string
}{
    Password: "SuperSecretPass123",
    APIKey:   "sk-multi-line-secret-key",
}` // #nosec G101

	result := &model.ScanResult{
		ScanID: "test-multiline",
		Status: "completed",
		Findings: []model.Finding{
			{
				ID:          "multiline-1",
				Type:        model.FindingTypeSecret,
				Severity:    model.SeverityHigh,
				Title:       "Multi-line secret",
				CodeSnippet: multiLineSnippet,
			},
		},
		Summary: model.Summary{Total: 1},
	}

	var buf bytes.Buffer
	err := formatter.Format(result, &buf)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	output := buf.String()

	// Both secrets on different lines should be masked
	if strings.Contains(output, "SuperSecretPass123") {
		t.Error("expected Password secret to be masked")
	}
	if strings.Contains(output, "sk-multi-line-secret-key") {
		t.Error("expected APIKey secret to be masked")
	}
}

func TestJSONFormatter_NilAndEmptyHandling(t *testing.T) {
	t.Parallel()
	formatter := &JSONFormatter{}

	t.Run("nil result", func(t *testing.T) {
		var buf bytes.Buffer
		err := formatter.Format(nil, &buf)
		if err != nil {
			t.Fatalf("Format failed on nil result: %v", err)
		}
		// Should encode nil as "null"
		if !strings.Contains(buf.String(), "null") {
			t.Error("expected null in output for nil result")
		}
	})

	t.Run("empty findings", func(t *testing.T) {
		result := &model.ScanResult{
			ScanID:   "empty",
			Status:   "completed",
			Findings: []model.Finding{},
		}
		var buf bytes.Buffer
		err := formatter.Format(result, &buf)
		if err != nil {
			t.Fatalf("Format failed: %v", err)
		}
		// Should succeed without panic
	})

	t.Run("finding with nil fix", func(t *testing.T) {
		result := &model.ScanResult{
			ScanID: "nil-fix",
			Status: "completed",
			Findings: []model.Finding{
				{
					ID:          "no-fix",
					CodeSnippet: `password = "test123456789"`,
					Fix:         nil,
				},
			},
		}
		var buf bytes.Buffer
		err := formatter.Format(result, &buf)
		if err != nil {
			t.Fatalf("Format failed: %v", err)
		}
		// Should mask snippet even with nil fix
		if strings.Contains(buf.String(), "test123456789") {
			t.Error("expected secret to be masked even with nil fix")
		}
	})
}
