package scan_test

import (
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/scan"
)

func TestMaskFixSecrets_NilFix(t *testing.T) {
	result := scan.MaskFixSecrets(nil)
	if result != nil {
		t.Errorf("MaskFixSecrets(nil) = %v, want nil", result)
	}
}

func TestMaskFixSecrets_EmptyFix(t *testing.T) {
	fix := &model.Fix{}
	result := scan.MaskFixSecrets(fix)

	if result == nil {
		t.Fatal("MaskFixSecrets returned nil for non-nil input")
	}
}

func TestMaskFixSecrets_MasksPatch(t *testing.T) {
	//nolint:gosec // G101: Test data contains fake secrets for testing masking functionality
	secretPatch := `--- a/config.go
+++ b/config.go
@@ -1,3 +1,3 @@
-api_key = "sk_live_secret123456789"
+api_key = os.Getenv("API_KEY")`

	fix := &model.Fix{
		Patch:       &secretPatch,
		Explanation: "Replace hardcoded secret with env var",
		IsValid:     true,
	}

	result := scan.MaskFixSecrets(fix)

	if result.Patch == nil {
		t.Fatal("Patch is nil after masking")
	}

	if strings.Contains(*result.Patch, "secret123456789") {
		t.Errorf("Secret not masked in Patch: %q", *result.Patch)
	}

	// Verify non-secret content is preserved
	if !strings.Contains(*result.Patch, "os.Getenv") {
		t.Errorf("Non-secret content missing from Patch: %q", *result.Patch)
	}
}

func TestMaskFixSecrets_MasksVulnerableCode(t *testing.T) {
	startLine := 1
	endLine := 1
	fix := &model.Fix{
		VulnerableCode: &model.CodeSnippetFix{
			FilePath:  "config.go",
			StartLine: &startLine,
			EndLine:   &endLine,
			Content:   `api_key = "sk_live_secret123456789"`,
		},
		Explanation: "Hardcoded secret detected",
	}

	result := scan.MaskFixSecrets(fix)

	if result.VulnerableCode == nil {
		t.Fatal("VulnerableCode is nil after masking")
	}

	if strings.Contains(result.VulnerableCode.Content, "secret123456789") {
		t.Errorf("Secret not masked in VulnerableCode.Content: %q", result.VulnerableCode.Content)
	}

	// Verify metadata is preserved
	if result.VulnerableCode.FilePath != "config.go" {
		t.Errorf("FilePath changed: got %q, want %q", result.VulnerableCode.FilePath, "config.go")
	}
}

func TestMaskFixSecrets_MasksProposedFixes(t *testing.T) {
	startLine := 1
	endLine := 1
	fix := &model.Fix{
		ProposedFixes: []model.CodeSnippetFix{
			{
				FilePath:  "config.go",
				StartLine: &startLine,
				EndLine:   &endLine,
				Content:   `api_key = "sk_live_secret123456789"`,
			},
			{
				FilePath:  "main.go",
				StartLine: &startLine,
				EndLine:   &endLine,
				Content:   `password = "admin123secretpassword"`,
			},
		},
	}

	result := scan.MaskFixSecrets(fix)

	if len(result.ProposedFixes) != 2 {
		t.Fatalf("Expected 2 proposed fixes, got %d", len(result.ProposedFixes))
	}

	for i, pf := range result.ProposedFixes {
		if strings.Contains(pf.Content, "secret") {
			t.Errorf("Secret not masked in ProposedFixes[%d].Content: %q", i, pf.Content)
		}
	}
}

func TestMaskFixSecrets_MasksPatchFiles(t *testing.T) {
	fix := &model.Fix{
		PatchFiles: map[string]string{
			"config.go": `api_key = "sk_live_secret123456789"`,
			"db.go":     `db_password = "supersecretdbpass"`,
		},
	}

	result := scan.MaskFixSecrets(fix)

	if len(result.PatchFiles) != 2 {
		t.Fatalf("Expected 2 patch files, got %d", len(result.PatchFiles))
	}

	for file, content := range result.PatchFiles {
		if strings.Contains(content, "secret") {
			t.Errorf("Secret not masked in PatchFiles[%q]: %q", file, content)
		}
	}
}

func TestMaskFixSecrets_DoesNotMaskTextFields(t *testing.T) {
	fix := &model.Fix{
		Explanation:     "Replace hardcoded secret with environment variable",
		Recommendations: "Use environment variables for sensitive data",
		Feedback:        "The fix correctly removes the secret",
		IsValid:         true,
	}

	result := scan.MaskFixSecrets(fix)

	// Text fields should NOT be masked
	if result.Explanation != fix.Explanation {
		t.Errorf("Explanation was modified: got %q, want %q", result.Explanation, fix.Explanation)
	}
	if result.Recommendations != fix.Recommendations {
		t.Errorf("Recommendations was modified: got %q, want %q", result.Recommendations, fix.Recommendations)
	}
	if result.Feedback != fix.Feedback {
		t.Errorf("Feedback was modified: got %q, want %q", result.Feedback, fix.Feedback)
	}
	if result.IsValid != fix.IsValid {
		t.Errorf("IsValid was modified: got %v, want %v", result.IsValid, fix.IsValid)
	}
}

func TestMaskFixSecrets_DoesNotModifyOriginal(t *testing.T) {
	//nolint:gosec // G101: Test data contains fake secrets for testing masking functionality
	secretPatch := `api_key = "sk_live_secret123456789"`
	originalPatch := secretPatch

	fix := &model.Fix{
		Patch: &secretPatch,
	}

	_ = scan.MaskFixSecrets(fix)

	// Verify original fix was not modified
	if *fix.Patch != originalPatch {
		t.Errorf("Original fix was modified: got %q, want %q", *fix.Patch, originalPatch)
	}
}

func TestMaskFixSecrets_AllFieldsPopulated(t *testing.T) {
	//nolint:gosec // G101: Test data contains fake secrets for testing masking functionality
	secretPatch := `api_key = "sk_live_secret123456789"`
	startLine := 1
	endLine := 1

	fix := &model.Fix{
		Patch: &secretPatch,
		VulnerableCode: &model.CodeSnippetFix{
			FilePath:  "config.go",
			StartLine: &startLine,
			EndLine:   &endLine,
			Content:   `api_key = "sk_live_secret123456789"`,
		},
		ProposedFixes: []model.CodeSnippetFix{
			{
				FilePath:  "config.go",
				StartLine: &startLine,
				EndLine:   &endLine,
				Content:   `api_key = "sk_live_newsecret789"`,
			},
		},
		PatchFiles: map[string]string{
			"config.go": `api_key = "sk_live_patchsecret"`,
		},
		Explanation:     "Fix explanation",
		Recommendations: "Recommendations text",
		Feedback:        "Feedback text",
		IsValid:         true,
	}

	result := scan.MaskFixSecrets(fix)

	// Verify all code fields are masked
	if strings.Contains(*result.Patch, "secret123456789") {
		t.Error("Patch still contains secret")
	}
	if strings.Contains(result.VulnerableCode.Content, "secret123456789") {
		t.Error("VulnerableCode.Content still contains secret")
	}
	if strings.Contains(result.ProposedFixes[0].Content, "newsecret789") {
		t.Error("ProposedFixes[0].Content still contains secret")
	}
	if strings.Contains(result.PatchFiles["config.go"], "patchsecret") {
		t.Error("PatchFiles still contains secret")
	}

	// Verify text fields are NOT masked
	if result.Explanation != fix.Explanation {
		t.Error("Explanation was modified")
	}
	if result.Recommendations != fix.Recommendations {
		t.Error("Recommendations was modified")
	}
}
