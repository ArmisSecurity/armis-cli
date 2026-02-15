package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/model"
)

func TestHumanFormatter_Format(t *testing.T) {
	formatter := &HumanFormatter{}

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
		},
		Summary: model.Summary{
			Total: 1,
			BySeverity: map[model.Severity]int{
				model.SeverityHigh: 1,
			},
		},
	}

	var buf bytes.Buffer
	err := formatter.Format(result, &buf)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "ARMIS SECURITY SCAN RESULTS") {
		t.Error("Expected header in output")
	}
	if !strings.Contains(output, "test-scan-123") {
		t.Error("Expected scan ID in output")
	}
	if !strings.Contains(output, "completed") {
		t.Error("Expected status in output")
	}
	if !strings.Contains(output, "SQL Injection") {
		t.Error("Expected finding title in output")
	}
}

func TestHumanFormatter_FormatWithOptions(t *testing.T) {
	formatter := &HumanFormatter{}

	result := &model.ScanResult{
		ScanID: "test-scan",
		Status: "completed",
		Findings: []model.Finding{
			{
				ID:       "1",
				Severity: model.SeverityHigh,
				Title:    "High Issue",
				CWEs:     []string{"CWE-79"},
			},
			{
				ID:       "2",
				Severity: model.SeverityMedium,
				Title:    "Medium Issue",
				CWEs:     []string{"CWE-79"},
			},
		},
		Summary: model.Summary{
			Total: 2,
		},
	}

	t.Run("group by severity", func(t *testing.T) {
		var buf bytes.Buffer
		opts := FormatOptions{GroupBy: "severity"}
		err := formatter.FormatWithOptions(result, &buf, opts)
		if err != nil {
			t.Fatalf("FormatWithOptions failed: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, "HIGH") {
			t.Error("Expected HIGH severity group")
		}
		if !strings.Contains(output, "MEDIUM") {
			t.Error("Expected MEDIUM severity group")
		}
	})

	t.Run("group by cwe", func(t *testing.T) {
		var buf bytes.Buffer
		opts := FormatOptions{GroupBy: "cwe"}
		err := formatter.FormatWithOptions(result, &buf, opts)
		if err != nil {
			t.Fatalf("FormatWithOptions failed: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, "CWE-79") {
			t.Error("Expected CWE-79 group")
		}
	})

	t.Run("no grouping", func(t *testing.T) {
		var buf bytes.Buffer
		opts := FormatOptions{GroupBy: "none"}
		err := formatter.FormatWithOptions(result, &buf, opts)
		if err != nil {
			t.Fatalf("FormatWithOptions failed: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, "High Issue") {
			t.Error("Expected finding in output")
		}
	})
}

func TestHumanFormatter_EmptyFindings(t *testing.T) {
	formatter := &HumanFormatter{}

	result := &model.ScanResult{
		ScanID:   "empty-scan",
		Status:   "completed",
		Findings: []model.Finding{},
		Summary: model.Summary{
			Total: 0,
		},
	}

	var buf bytes.Buffer
	err := formatter.Format(result, &buf)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "ARMIS SECURITY SCAN RESULTS") {
		t.Error("Expected header even with no findings")
	}
	if strings.Contains(output, "FINDINGS") {
		t.Error("Should not show FINDINGS section when empty")
	}
}

func TestIndentWriter(t *testing.T) {
	t.Run("writes with prefix", func(t *testing.T) {
		var buf bytes.Buffer
		iw := &indentWriter{
			w:      &buf,
			prefix: "  ",
			atBOL:  true,
		}

		n, err := iw.Write([]byte("test"))
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}
		if n != 4 {
			t.Errorf("Expected 4 bytes written, got %d", n)
		}
		if buf.String() != "  test" {
			t.Errorf("Expected '  test', got %q", buf.String())
		}
	})

	t.Run("handles newlines", func(t *testing.T) {
		var buf bytes.Buffer
		iw := &indentWriter{
			w:      &buf,
			prefix: "> ",
			atBOL:  true,
		}

		_, _ = iw.Write([]byte("line1\nline2\n"))
		expected := "> line1\n> line2\n"
		if buf.String() != expected {
			t.Errorf("Expected %q, got %q", expected, buf.String())
		}
	})

	t.Run("multiple writes", func(t *testing.T) {
		var buf bytes.Buffer
		iw := &indentWriter{
			w:      &buf,
			prefix: "- ",
			atBOL:  true,
		}

		_, _ = iw.Write([]byte("first\n"))
		_, _ = iw.Write([]byte("second"))
		expected := "- first\n- second"
		if buf.String() != expected {
			t.Errorf("Expected %q, got %q", expected, buf.String())
		}
	})
}

func TestSortFindingsBySeverity(t *testing.T) {
	findings := []model.Finding{
		{ID: "1", Severity: model.SeverityLow},
		{ID: "2", Severity: model.SeverityCritical},
		{ID: "3", Severity: model.SeverityMedium},
		{ID: "4", Severity: model.SeverityHigh},
	}

	sorted := sortFindingsBySeverity(findings)

	if sorted[0].Severity != model.SeverityCritical {
		t.Errorf("Expected first to be CRITICAL, got %s", sorted[0].Severity)
	}
	if sorted[1].Severity != model.SeverityHigh {
		t.Errorf("Expected second to be HIGH, got %s", sorted[1].Severity)
	}
	if sorted[2].Severity != model.SeverityMedium {
		t.Errorf("Expected third to be MEDIUM, got %s", sorted[2].Severity)
	}
	if sorted[3].Severity != model.SeverityLow {
		t.Errorf("Expected fourth to be LOW, got %s", sorted[3].Severity)
	}
}

func TestFormattedOutputWithoutColors(t *testing.T) {
	// Initialize with no colors using cli package
	cli.InitColors(cli.ColorModeNever)
	SyncColors()

	// Restore colors after test
	defer func() {
		cli.InitColors(cli.ColorModeAlways)
		SyncColors()
	}()

	formatter := &HumanFormatter{}
	result := &model.ScanResult{
		ScanID: "test-scan",
		Status: "completed",
		Findings: []model.Finding{
			{
				ID:       "1",
				Severity: model.SeverityCritical,
				Title:    "Critical Issue",
			},
			{
				ID:       "2",
				Severity: model.SeverityHigh,
				Title:    "High Issue",
			},
		},
		Summary: model.Summary{
			Total: 2,
			BySeverity: map[model.Severity]int{
				model.SeverityCritical: 1,
				model.SeverityHigh:     1,
			},
		},
	}

	var buf bytes.Buffer
	err := formatter.Format(result, &buf)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	output := buf.String()

	// Verify no ANSI escape codes in output
	if strings.Contains(output, "\033[") {
		t.Error("Output should not contain ANSI escape codes when colors are disabled")
	}

	// Verify content is still present
	if !strings.Contains(output, "Critical Issue") {
		t.Error("Output should contain finding title")
	}
	if !strings.Contains(output, "CRITICAL") {
		t.Error("Output should contain severity")
	}
}

func TestIsGitRepo(t *testing.T) {
	t.Run("non-existent directory", func(t *testing.T) {
		result := isGitRepo("/nonexistent/path")
		if result {
			t.Error("Expected false for non-existent directory")
		}
	})

	t.Run("temp directory without git", func(t *testing.T) {
		tmpDir := t.TempDir()
		result := isGitRepo(tmpDir)
		if result {
			t.Error("Expected false for directory without .git")
		}
	})
}

func TestScanDuration(t *testing.T) {
	tests := []struct {
		name      string
		startedAt string
		endedAt   string
		expected  string
	}{
		{
			name:      "empty times",
			startedAt: "",
			endedAt:   "",
			expected:  "",
		},
		{
			name:      "invalid format",
			startedAt: "invalid",
			endedAt:   "invalid",
			expected:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &model.ScanResult{
				StartedAt: tt.startedAt,
				EndedAt:   tt.endedAt,
			}
			duration := scanDuration(result)
			if duration != tt.expected {
				t.Errorf("scanDuration() = %q, want %q", duration, tt.expected)
			}
		})
	}
}

func TestPluralize(t *testing.T) {
	tests := []struct {
		word     string
		count    int
		expected string
	}{
		{"issue", 0, "issues"},
		{"issue", 1, "issue"},
		{"issue", 2, "issues"},
		{"issue", 100, "issues"},
		{"finding", 1, "finding"},
		{"finding", 5, "findings"},
	}

	for _, tt := range tests {
		result := pluralize(tt.word, tt.count)
		if result != tt.expected {
			t.Errorf("pluralize(%q, %d) = %q, want %q", tt.word, tt.count, result, tt.expected)
		}
	}
}

func TestRenderBriefStatus(t *testing.T) {
	tests := []struct {
		name     string
		result   *model.ScanResult
		contains []string
	}{
		{
			name: "no findings",
			result: &model.ScanResult{
				Summary: model.Summary{Total: 0},
			},
			contains: []string{"No issues found"},
		},
		{
			name: "single finding",
			result: &model.ScanResult{
				Summary: model.Summary{
					Total: 1,
					BySeverity: map[model.Severity]int{
						model.SeverityHigh: 1,
					},
				},
			},
			contains: []string{"1 issue", "1 high"},
		},
		{
			name: "multiple severities",
			result: &model.ScanResult{
				Summary: model.Summary{
					Total: 5,
					BySeverity: map[model.Severity]int{
						model.SeverityCritical: 2,
						model.SeverityHigh:     1,
						model.SeverityMedium:   2,
					},
				},
			},
			contains: []string{"5 issues", "2 critical", "1 high", "2 medium"},
		},
		{
			name: "all severities",
			result: &model.ScanResult{
				Summary: model.Summary{
					Total: 10,
					BySeverity: map[model.Severity]int{
						model.SeverityCritical: 1,
						model.SeverityHigh:     2,
						model.SeverityMedium:   3,
						model.SeverityLow:      2,
						model.SeverityInfo:     2,
					},
				},
			},
			contains: []string{"10 issues", "1 critical", "2 high", "3 medium", "2 low", "2 info"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := renderBriefStatus(&buf, tt.result)
			if err != nil {
				t.Fatalf("renderBriefStatus failed: %v", err)
			}
			output := buf.String()
			for _, expected := range tt.contains {
				if !strings.Contains(output, expected) {
					t.Errorf("expected output to contain %q, got %q", expected, output)
				}
			}
		})
	}
}

func TestHybridOutputStructure(t *testing.T) {
	formatter := &HumanFormatter{}

	result := &model.ScanResult{
		ScanID: "test-hybrid",
		Status: "completed",
		Findings: []model.Finding{
			{
				ID:       "1",
				Severity: model.SeverityCritical,
				Title:    "Critical Issue",
			},
			{
				ID:       "2",
				Severity: model.SeverityHigh,
				Title:    "High Issue",
			},
		},
		Summary: model.Summary{
			Total: 2,
			BySeverity: map[model.Severity]int{
				model.SeverityCritical: 1,
				model.SeverityHigh:     1,
			},
		},
	}

	var buf bytes.Buffer
	err := formatter.Format(result, &buf)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	output := buf.String()

	// Verify brief status appears before FINDINGS
	briefStatusIdx := strings.Index(output, "2 issues")
	findingsIdx := strings.Index(output, "FINDINGS")
	if briefStatusIdx == -1 {
		t.Error("Expected brief status line in output")
	}
	if findingsIdx == -1 {
		t.Error("Expected FINDINGS section in output")
	}
	if briefStatusIdx > findingsIdx {
		t.Error("Brief status should appear before FINDINGS section")
	}

	// Verify summary dashboard appears after FINDINGS
	// The minimal styled output uses "SCAN COMPLETE" in the summary box
	dashboardIdx := strings.Index(output, "SCAN COMPLETE")
	if dashboardIdx == -1 {
		t.Error("Expected summary dashboard in output")
	}
	if dashboardIdx < findingsIdx {
		t.Error("Summary dashboard should appear after FINDINGS section")
	}
}

// TestDiffParsing tests the enhanced diff parsing functionality
func TestDiffParsing(t *testing.T) {
	// Ensure no color mode for predictable output
	cli.InitColors(cli.ColorModeNever)
	SyncStylesWithColorMode()

	t.Run("parseDiffHunk extracts line numbers", func(t *testing.T) {
		oldStart, oldCount, newStart, newCount := parseDiffHunk("@@ -31,6 +31,8 @@")
		if oldStart != 31 || oldCount != 6 || newStart != 31 || newCount != 8 {
			t.Errorf("Expected (31,6,31,8), got (%d,%d,%d,%d)", oldStart, oldCount, newStart, newCount)
		}

		// Single line hunk (no count)
		oldStart, _, newStart, _ = parseDiffHunk("@@ -1 +1 @@")
		if oldStart != 1 || newStart != 1 {
			t.Errorf("Expected single line hunk parsing, got (%d,%d)", oldStart, newStart)
		}
	})

	t.Run("parseDiffLines creates structured output", func(t *testing.T) {
		patch := `@@ -51,4 +53,4 @@
 context line
-removed line
+added line`
		lines := parseDiffLines(patch)

		if len(lines) != 4 {
			t.Fatalf("Expected 4 lines, got %d", len(lines))
		}

		// Check hunk line
		if lines[0].Type != DiffLineHunk {
			t.Error("First line should be hunk header")
		}

		// Check context line (leading space is stripped to match add/remove line handling)
		if lines[1].Type != DiffLineContext {
			t.Error("Second line should be context")
		}
		if lines[1].Content != "context line" {
			t.Errorf("Context content should be 'context line', got %q", lines[1].Content)
		}

		// Check remove line
		if lines[2].Type != DiffLineRemove {
			t.Error("Third line should be remove")
		}
		if lines[2].Content != "removed line" {
			t.Errorf("Remove content should be 'removed line', got %q", lines[2].Content)
		}
		if lines[2].OldNum != 52 { // 51 + 1 (after context line)
			t.Errorf("Remove line number should be 52, got %d", lines[2].OldNum)
		}

		// Check add line
		if lines[3].Type != DiffLineAdd {
			t.Error("Fourth line should be add")
		}
		if lines[3].NewNum != 54 { // 53 + 1 (after context line)
			t.Errorf("Add line number should be 54, got %d", lines[3].NewNum)
		}
	})

	t.Run("findInlineChanges detects word differences", func(t *testing.T) {
		oldLine := "app.run(debug=True)"
		newLine := "app.run(debug=False)"

		oldSpans, newSpans := findInlineChanges(oldLine, newLine)

		// Should find "True" and "False" as the differing parts
		if len(oldSpans) == 0 || len(newSpans) == 0 {
			t.Error("Expected inline changes to be detected")
		}
	})

	t.Run("formatDiffWithColorsStyled produces formatted output", func(t *testing.T) {
		patch := `@@ -1,2 +1,2 @@
 unchanged
-old
+new`
		output := formatDiffWithColorsStyled(patch)

		// Should contain line numbers
		if !strings.Contains(output, "1") {
			t.Error("Expected line numbers in output")
		}
		// Should contain +/- markers (no gutter - matches code snippet style)
		if !strings.Contains(output, "+") || !strings.Contains(output, "-") {
			t.Error("Expected +/- markers in output")
		}
	})

	t.Run("empty lines in diff are preserved", func(t *testing.T) {
		patch := `@@ -1,3 +1,3 @@
 first

 third`
		lines := parseDiffLines(patch)

		// Should have 4 lines: hunk + 3 content lines (including empty)
		if len(lines) != 4 {
			t.Errorf("Expected 4 lines (preserving empty line), got %d", len(lines))
		}
	})
}

func TestHumanFormatter_LightTheme(t *testing.T) {
	// Enable colors and force light theme detection
	cli.InitColors(cli.ColorModeAlways)

	// Import lipgloss to set theme
	// Note: We can't directly call lipgloss.SetHasDarkBackground here
	// because it would require importing lipgloss. Instead, we test that
	// the formatter produces valid output regardless of theme detection.

	// Reset styles to pick up any theme changes
	SyncStylesWithColorMode()
	defer func() {
		// Restore default state
		cli.InitColors(cli.ColorModeAlways)
		SyncStylesWithColorMode()
	}()

	formatter := &HumanFormatter{}
	result := &model.ScanResult{
		ScanID: "light-theme-test",
		Status: "completed",
		Findings: []model.Finding{
			{
				ID:       "1",
				Severity: model.SeverityCritical,
				Title:    "Critical Issue",
				Type:     model.FindingTypeVulnerability,
			},
			{
				ID:       "2",
				Severity: model.SeverityMedium,
				Title:    "Medium Issue",
				Type:     model.FindingTypeSCA,
			},
		},
		Summary: model.Summary{
			Total: 2,
			BySeverity: map[model.Severity]int{
				model.SeverityCritical: 1,
				model.SeverityMedium:   1,
			},
		},
	}

	var buf bytes.Buffer
	err := formatter.Format(result, &buf)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "ARMIS SECURITY SCAN RESULTS") {
		t.Error("Expected header in output")
	}
	if !strings.Contains(output, "Critical Issue") {
		t.Error("Expected critical finding in output")
	}
	if !strings.Contains(output, "Medium Issue") {
		t.Error("Expected medium finding in output")
	}
}
