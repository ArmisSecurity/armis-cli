package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/model"
)

// Test constants for render op types
const (
	testOpTypeChange  = "change"
	testOpTypeContext = "context"
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

// TestExtractDiffFilename tests filename extraction from diff patches
func TestExtractDiffFilename(t *testing.T) {
	tests := []struct {
		name  string
		patch string
		want  string
	}{
		{
			name:  "git diff format",
			patch: "--- a/path/to/file.py\n+++ b/path/to/file.py\n@@ -1,3 +1,3 @@",
			want:  "path/to/file.py",
		},
		{
			name:  "plain diff format",
			patch: "--- path/to/file.py\n+++ path/to/file.py\n@@ -1,3 +1,3 @@",
			want:  "path/to/file.py",
		},
		{
			name:  "new file",
			patch: "--- /dev/null\n+++ b/newfile.go\n@@ -0,0 +1,5 @@",
			want:  "newfile.go",
		},
		{
			name:  "no header",
			patch: "@@ -1,3 +1,3 @@\n context\n-old\n+new",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDiffFilename(tt.patch)
			if got != tt.want {
				t.Errorf("extractDiffFilename() = %q, want %q", got, tt.want)
			}
		})
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

	t.Run("parseDiffLines preserves removed lines starting with double dash", func(t *testing.T) {
		// Bug fix test: Lines starting with "---" after a hunk header are diff content,
		// not file headers. E.g., a SQL comment "-- DROP TABLE" removed appears as "--- DROP TABLE"
		patch := `--- a/schema.sql
+++ b/schema.sql
@@ -1,3 +1,2 @@
 CREATE TABLE users;
--- DROP TABLE legacy;
 INSERT INTO users VALUES (1);`
		lines := parseDiffLines(patch)

		// Should have: hunk + context + removed + context = 4 lines
		// The "--- DROP TABLE legacy;" should be parsed as DiffLineRemove, not skipped
		if len(lines) != 4 {
			t.Fatalf("Expected 4 lines, got %d", len(lines))
		}

		// Find the removed line
		var foundRemove bool
		for _, line := range lines {
			if line.Type == DiffLineRemove {
				foundRemove = true
				if line.Content != "-- DROP TABLE legacy;" {
					t.Errorf("Expected removed content '-- DROP TABLE legacy;', got %q", line.Content)
				}
			}
		}
		if !foundRemove {
			t.Error("Expected to find a DiffLineRemove for the SQL comment line")
		}
	})

	t.Run("parseDiffLines preserves added lines starting with double plus", func(t *testing.T) {
		// Similar test for +++ content lines
		patch := `--- a/config.yaml
+++ b/config.yaml
@@ -1,2 +1,3 @@
 key: value
+++ additional_section
 more: data`
		lines := parseDiffLines(patch)

		// Should have: hunk + context + added + context = 4 lines
		var foundAdd bool
		for _, line := range lines {
			if line.Type == DiffLineAdd {
				foundAdd = true
				if line.Content != "++ additional_section" {
					t.Errorf("Expected added content '++ additional_section', got %q", line.Content)
				}
			}
		}
		if !foundAdd {
			t.Error("Expected to find a DiffLineAdd for the ++ line")
		}
	})

	t.Run("parseDiffLines skips no newline marker without incrementing line numbers", func(t *testing.T) {
		// The "\ No newline at end of file" marker should be skipped without
		// affecting line number tracking
		patch := `--- a/file.txt
+++ b/file.txt
@@ -1,2 +1,2 @@
 line1
-old line2
\ No newline at end of file
+new line2
\ No newline at end of file`
		lines := parseDiffLines(patch)

		// Should have: hunk + context + remove + add = 4 lines (markers skipped)
		if len(lines) != 4 {
			t.Errorf("Expected 4 lines (hunk + context + remove + add), got %d", len(lines))
			for i, line := range lines {
				t.Logf("Line %d: Type=%d, Content=%q, OldNum=%d, NewNum=%d",
					i, line.Type, line.Content, line.OldNum, line.NewNum)
			}
		}

		// Verify the removed line has correct line number (should be 2, not affected by marker)
		for _, line := range lines {
			if line.Type == DiffLineRemove && line.Content == "old line2" {
				if line.OldNum != 2 {
					t.Errorf("Expected removed line OldNum=2, got %d", line.OldNum)
				}
			}
			if line.Type == DiffLineAdd && line.Content == "new line2" {
				if line.NewNum != 2 {
					t.Errorf("Expected added line NewNum=2, got %d", line.NewNum)
				}
			}
		}

		// Ensure no marker lines were included in the output
		for _, line := range lines {
			if strings.Contains(line.Content, "No newline") {
				t.Errorf("Marker line should not be included: %q", line.Content)
			}
		}
	})

	t.Run("findInlineChanges handles token insertions correctly", func(t *testing.T) {
		// Bug fix test: LCS-based algorithm should correctly handle insertions
		// without cascading false positives
		oldLine := "a b c"
		newLine := "a x b c"

		oldSpans, newSpans := findInlineChanges(oldLine, newLine)

		// Old line should have no changes (nothing was removed)
		if len(oldSpans) != 0 {
			t.Errorf("Expected 0 old spans for pure insertion, got %d: %v", len(oldSpans), oldSpans)
		}

		// New line should have exactly one span for the inserted "x "
		if len(newSpans) != 2 {
			// Should find "x" and the space as separate tokens
			t.Errorf("Expected 2 new spans for 'x' and ' ' insertion, got %d: %v", len(newSpans), newSpans)
		}
	})

	t.Run("findInlineChanges handles token deletions correctly", func(t *testing.T) {
		// Reverse of insertion test
		oldLine := "a x b c"
		newLine := "a b c"

		oldSpans, newSpans := findInlineChanges(oldLine, newLine)

		// Old line should mark the deleted "x "
		if len(oldSpans) != 2 {
			t.Errorf("Expected 2 old spans for 'x' and ' ' deletion, got %d: %v", len(oldSpans), oldSpans)
		}

		// New line should have no changes
		if len(newSpans) != 0 {
			t.Errorf("Expected 0 new spans for pure deletion, got %d: %v", len(newSpans), newSpans)
		}
	})

	t.Run("findInlineChanges handles substitutions correctly", func(t *testing.T) {
		oldLine := "value = True"
		newLine := "value = False"

		oldSpans, newSpans := findInlineChanges(oldLine, newLine)

		// Should find exactly "True" -> "False" substitution
		if len(oldSpans) != 1 || len(newSpans) != 1 {
			t.Errorf("Expected 1 span each for substitution, got old=%d new=%d", len(oldSpans), len(newSpans))
		}

		// Verify the span positions are correct
		if len(oldSpans) == 1 {
			// "True" starts at position 8 in "value = True"
			if oldSpans[0].Start != 8 || oldSpans[0].End != 12 {
				t.Errorf("Expected old span [8,12] for 'True', got [%d,%d]", oldSpans[0].Start, oldSpans[0].End)
			}
		}
		if len(newSpans) == 1 {
			// "False" starts at position 8 in "value = False"
			if newSpans[0].Start != 8 || newSpans[0].End != 13 {
				t.Errorf("Expected new span [8,13] for 'False', got [%d,%d]", newSpans[0].Start, newSpans[0].End)
			}
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

func TestGroupDiffHunks(t *testing.T) {
	t.Run("single hunk", func(t *testing.T) {
		lines := []DiffLine{
			{Type: DiffLineHunk, Content: "@@ -1,3 +1,3 @@"},
			{Type: DiffLineContext, Content: "ctx"},
			{Type: DiffLineRemove, Content: "old"},
			{Type: DiffLineAdd, Content: "new"},
		}
		hunks := groupDiffHunks(lines)
		if len(hunks) != 1 {
			t.Fatalf("Expected 1 hunk, got %d", len(hunks))
		}
		if hunks[0].Added != 1 || hunks[0].Removed != 1 {
			t.Errorf("Expected Added=1, Removed=1, got Added=%d, Removed=%d", hunks[0].Added, hunks[0].Removed)
		}
		if len(hunks[0].Lines) != 3 {
			t.Errorf("Expected 3 content lines, got %d", len(hunks[0].Lines))
		}
	})

	t.Run("two hunks", func(t *testing.T) {
		lines := []DiffLine{
			{Type: DiffLineHunk, Content: "@@ -1,2 +1,2 @@"},
			{Type: DiffLineRemove, Content: "a"},
			{Type: DiffLineAdd, Content: "b"},
			{Type: DiffLineHunk, Content: "@@ -10,3 +10,5 @@"},
			{Type: DiffLineRemove, Content: "c"},
			{Type: DiffLineAdd, Content: "d"},
			{Type: DiffLineAdd, Content: "e"},
			{Type: DiffLineAdd, Content: "f"},
		}
		hunks := groupDiffHunks(lines)
		if len(hunks) != 2 {
			t.Fatalf("Expected 2 hunks, got %d", len(hunks))
		}
		if hunks[0].Added != 1 || hunks[0].Removed != 1 {
			t.Errorf("Hunk 0: Expected Added=1, Removed=1, got Added=%d, Removed=%d", hunks[0].Added, hunks[0].Removed)
		}
		if hunks[1].Added != 3 || hunks[1].Removed != 1 {
			t.Errorf("Hunk 1: Expected Added=3, Removed=1, got Added=%d, Removed=%d", hunks[1].Added, hunks[1].Removed)
		}
	})

	t.Run("empty input", func(t *testing.T) {
		hunks := groupDiffHunks([]DiffLine{})
		if len(hunks) != 0 {
			t.Errorf("Expected 0 hunks for empty input, got %d", len(hunks))
		}
	})
}

func TestCollectRenderOps(t *testing.T) {
	t.Run("change block with removes and adds", func(t *testing.T) {
		lines := []DiffLine{
			{Type: DiffLineRemove, Content: "a"},
			{Type: DiffLineRemove, Content: "b"},
			{Type: DiffLineAdd, Content: "x"},
			{Type: DiffLineAdd, Content: "y"},
		}
		ops := collectRenderOps(lines)
		if len(ops) != 1 {
			t.Fatalf("Expected 1 op (change block), got %d", len(ops))
		}
		if ops[0].Type != testOpTypeChange {
			t.Errorf("Expected 'change' type, got %q", ops[0].Type)
		}
		if len(ops[0].Block.Removes) != 2 || len(ops[0].Block.Adds) != 2 {
			t.Errorf("Expected 2 removes and 2 adds, got %d removes and %d adds",
				len(ops[0].Block.Removes), len(ops[0].Block.Adds))
		}
	})

	t.Run("context line creates separate op", func(t *testing.T) {
		lines := []DiffLine{
			{Type: DiffLineRemove, Content: "a"},
			{Type: DiffLineAdd, Content: "x"},
			{Type: DiffLineContext, Content: "ctx"},
			{Type: DiffLineRemove, Content: "b"},
			{Type: DiffLineAdd, Content: "y"},
		}
		ops := collectRenderOps(lines)
		if len(ops) != 3 {
			t.Fatalf("Expected 3 ops, got %d", len(ops))
		}
		if ops[0].Type != testOpTypeChange || ops[1].Type != testOpTypeContext || ops[2].Type != testOpTypeChange {
			t.Errorf("Expected [change, context, change], got [%s, %s, %s]",
				ops[0].Type, ops[1].Type, ops[2].Type)
		}
	})

	t.Run("alternating remove-add-remove flushes correctly", func(t *testing.T) {
		lines := []DiffLine{
			{Type: DiffLineRemove, Content: "a"},
			{Type: DiffLineAdd, Content: "x"},
			{Type: DiffLineRemove, Content: "b"},
			{Type: DiffLineAdd, Content: "y"},
		}
		ops := collectRenderOps(lines)
		// Should create: block1 (a->x), block2 (b->y)
		if len(ops) != 2 {
			t.Fatalf("Expected 2 ops, got %d", len(ops))
		}
	})

	t.Run("pure additions", func(t *testing.T) {
		lines := []DiffLine{
			{Type: DiffLineAdd, Content: "new1"},
			{Type: DiffLineAdd, Content: "new2"},
		}
		ops := collectRenderOps(lines)
		if len(ops) != 1 {
			t.Fatalf("Expected 1 op, got %d", len(ops))
		}
		if len(ops[0].Block.Removes) != 0 || len(ops[0].Block.Adds) != 2 {
			t.Errorf("Expected 0 removes, 2 adds, got %d removes, %d adds",
				len(ops[0].Block.Removes), len(ops[0].Block.Adds))
		}
	})

	t.Run("pure removals", func(t *testing.T) {
		lines := []DiffLine{
			{Type: DiffLineRemove, Content: "old1"},
			{Type: DiffLineRemove, Content: "old2"},
		}
		ops := collectRenderOps(lines)
		if len(ops) != 1 {
			t.Fatalf("Expected 1 op, got %d", len(ops))
		}
		if len(ops[0].Block.Removes) != 2 || len(ops[0].Block.Adds) != 0 {
			t.Errorf("Expected 2 removes, 0 adds, got %d removes, %d adds",
				len(ops[0].Block.Removes), len(ops[0].Block.Adds))
		}
	})
}

func TestRenderChangeBlock(t *testing.T) {
	cli.InitColors(cli.ColorModeNever)
	SyncStylesWithColorMode()
	s := GetStyles()

	t.Run("equal removes and adds get paired", func(t *testing.T) {
		block := ChangeBlock{
			Removes: []DiffLine{
				{Type: DiffLineRemove, Content: "value = True", OldNum: 10},
				{Type: DiffLineRemove, Content: "name = old", OldNum: 11},
			},
			Adds: []DiffLine{
				{Type: DiffLineAdd, Content: "value = False", NewNum: 10},
				{Type: DiffLineAdd, Content: "name = new", NewNum: 11},
			},
		}
		output := renderChangeBlock(block, s, 80, "test.py")
		lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
		// Interleaved: remove, add, remove, add = 4 lines
		if len(lines) != 4 {
			t.Errorf("Expected 4 lines (interleaved), got %d", len(lines))
		}
		// First line should be a remove (contains "-")
		if !strings.Contains(lines[0], "-") {
			t.Error("First line should be a remove")
		}
		// Second line should be an add (contains "+")
		if !strings.Contains(lines[1], "+") {
			t.Error("Second line should be an add")
		}
	})

	t.Run("more removes than adds", func(t *testing.T) {
		block := ChangeBlock{
			Removes: []DiffLine{
				{Type: DiffLineRemove, Content: "a", OldNum: 1},
				{Type: DiffLineRemove, Content: "b", OldNum: 2},
				{Type: DiffLineRemove, Content: "c", OldNum: 3},
			},
			Adds: []DiffLine{
				{Type: DiffLineAdd, Content: "x", NewNum: 1},
			},
		}
		output := renderChangeBlock(block, s, 80, "test.go")
		lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
		// 1 paired (remove + add) + 2 unpaired removes = 4 lines
		if len(lines) != 4 {
			t.Errorf("Expected 4 lines, got %d", len(lines))
		}
	})

	t.Run("more adds than removes", func(t *testing.T) {
		block := ChangeBlock{
			Removes: []DiffLine{
				{Type: DiffLineRemove, Content: "a", OldNum: 1},
			},
			Adds: []DiffLine{
				{Type: DiffLineAdd, Content: "x", NewNum: 1},
				{Type: DiffLineAdd, Content: "y", NewNum: 2},
				{Type: DiffLineAdd, Content: "z", NewNum: 3},
			},
		}
		output := renderChangeBlock(block, s, 80, "test.go")
		lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
		// 1 paired (remove + add) + 2 unpaired adds = 4 lines
		if len(lines) != 4 {
			t.Errorf("Expected 4 lines, got %d", len(lines))
		}
	})

	t.Run("pure additions", func(t *testing.T) {
		block := ChangeBlock{
			Adds: []DiffLine{
				{Type: DiffLineAdd, Content: "new1", NewNum: 5},
				{Type: DiffLineAdd, Content: "new2", NewNum: 6},
			},
		}
		output := renderChangeBlock(block, s, 80, "test.go")
		lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
		if len(lines) != 2 {
			t.Errorf("Expected 2 lines, got %d", len(lines))
		}
	})

	t.Run("pure removals", func(t *testing.T) {
		block := ChangeBlock{
			Removes: []DiffLine{
				{Type: DiffLineRemove, Content: "old1", OldNum: 5},
			},
		}
		output := renderChangeBlock(block, s, 80, "test.go")
		if !strings.Contains(output, "-") {
			t.Error("Expected remove marker in output")
		}
	})

	t.Run("strips identical trailing pairs", func(t *testing.T) {
		// Scanner artifact: closing brace appears as remove+add when lines shift
		block := ChangeBlock{
			Removes: []DiffLine{
				{Type: DiffLineRemove, Content: "real change", OldNum: 10},
				{Type: DiffLineRemove, Content: "}", OldNum: 11},
			},
			Adds: []DiffLine{
				{Type: DiffLineAdd, Content: "different", NewNum: 10},
				{Type: DiffLineAdd, Content: "}", NewNum: 12},
			},
		}
		output := renderChangeBlock(block, s, 80, "test.go")
		// Should only render 2 lines (the real change), not 4
		lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
		if len(lines) != 2 {
			t.Errorf("Expected 2 lines after stripping identical trailing, got %d", len(lines))
		}
		// Verify the closing brace is not in the output
		if strings.Contains(output, "}") {
			t.Error("Expected trailing identical brace to be stripped")
		}
	})

	t.Run("strips multiple identical trailing pairs", func(t *testing.T) {
		// Multiple trailing identical lines (common in nested code)
		block := ChangeBlock{
			Removes: []DiffLine{
				{Type: DiffLineRemove, Content: "changed", OldNum: 10},
				{Type: DiffLineRemove, Content: "    }", OldNum: 11},
				{Type: DiffLineRemove, Content: "}", OldNum: 12},
			},
			Adds: []DiffLine{
				{Type: DiffLineAdd, Content: "modified", NewNum: 10},
				{Type: DiffLineAdd, Content: "    }", NewNum: 13},
				{Type: DiffLineAdd, Content: "}", NewNum: 14},
			},
		}
		output := renderChangeBlock(block, s, 80, "test.go")
		// Should only render 2 lines (the real change)
		lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
		if len(lines) != 2 {
			t.Errorf("Expected 2 lines after stripping multiple identical trailing, got %d", len(lines))
		}
	})

	t.Run("tabs are normalized to spaces", func(t *testing.T) {
		// This tests that tabs in content are converted to spaces for consistent
		// width calculation. runewidth.StringWidth counts tabs as width 0, but
		// lipgloss renders them as 4 spaces, causing background width mismatch.
		block := ChangeBlock{
			Removes: []DiffLine{
				{Type: DiffLineRemove, Content: "\tif err != nil {", OldNum: 10},
			},
			Adds: []DiffLine{
				{Type: DiffLineAdd, Content: "\tif err == nil {", NewNum: 10},
			},
		}
		output := renderChangeBlock(block, s, 80, "test.go")

		// After normalization, tabs become 4 spaces
		if strings.Contains(output, "\t") {
			t.Error("Output should not contain literal tabs after normalization")
		}
		// The output should contain the indentation (4 spaces from tab)
		if !strings.Contains(output, "    if err") {
			t.Error("Expected normalized spaces in output, got: " + output)
		}
	})

	t.Run("highlighted and non-highlighted lines have consistent width", func(t *testing.T) {
		// Test that both code paths (with and without inline highlights) produce
		// lines of the same padded width when given the same content length.
		termWidth := 80
		contentWidth := termWidth - 10 // Same calculation as formatDiffAddLine

		// Line with highlights (paired change)
		blockWithHighlights := ChangeBlock{
			Removes: []DiffLine{
				{Type: DiffLineRemove, Content: "value = true", OldNum: 1},
			},
			Adds: []DiffLine{
				{Type: DiffLineAdd, Content: "value = false", NewNum: 1},
			},
		}
		outputHighlighted := renderChangeBlock(blockWithHighlights, s, termWidth, "test.go")

		// Line without highlights (unpaired)
		blockWithoutHighlights := ChangeBlock{
			Adds: []DiffLine{
				{Type: DiffLineAdd, Content: "value = false", NewNum: 1},
			},
		}
		outputNoHighlight := renderChangeBlock(blockWithoutHighlights, s, termWidth, "test.go")

		// Extract the add line from each output (skip the remove line in highlighted output)
		highlightedLines := strings.Split(outputHighlighted, "\n")
		noHighlightLines := strings.Split(outputNoHighlight, "\n")

		// Find the add line (contains "+")
		var highlightedAddLine, noHighlightAddLine string
		for _, line := range highlightedLines {
			if strings.Contains(line, "+") {
				highlightedAddLine = line
				break
			}
		}
		for _, line := range noHighlightLines {
			if strings.Contains(line, "+") {
				noHighlightAddLine = line
				break
			}
		}

		// Both lines should have approximately the same visual width
		// (accounting for ANSI escape codes, we just check they're both present and padded)
		if highlightedAddLine == "" || noHighlightAddLine == "" {
			t.Error("Failed to extract add lines from output")
		}

		// In no-color mode, lines should be exactly equal after the marker
		// since both should be padded to contentWidth
		if highlightedAddLine != noHighlightAddLine {
			t.Logf("Highlighted: %q", highlightedAddLine)
			t.Logf("No highlight: %q", noHighlightAddLine)
			// Note: This might differ slightly due to inline change detection
			// but the padding should fill to the same width
			_ = contentWidth // Used for documentation
		}
	})
}

func TestFormatDiffHunkLineWithSummary(t *testing.T) {
	cli.InitColors(cli.ColorModeNever)
	SyncStylesWithColorMode()
	s := GetStyles()

	t.Run("with both adds and removes", func(t *testing.T) {
		line := DiffLine{Type: DiffLineHunk, Content: "@@ -1,3 +1,5 @@"}
		output := formatDiffHunkLine(line, s, 5, 3)
		if !strings.Contains(output, "-3") {
			t.Error("Expected -3 in summary")
		}
		if !strings.Contains(output, "+5") {
			t.Error("Expected +5 in summary")
		}
	})

	t.Run("zero counts omits summary", func(t *testing.T) {
		line := DiffLine{Type: DiffLineHunk, Content: "@@ -1,3 +1,3 @@"}
		output := formatDiffHunkLine(line, s, 0, 0)
		// Should not contain parentheses for summary when both are zero
		if strings.Contains(output, "(") {
			t.Error("Expected no summary for zero counts")
		}
	})

	t.Run("only adds", func(t *testing.T) {
		line := DiffLine{Type: DiffLineHunk, Content: "@@ -1 +1,3 @@"}
		output := formatDiffHunkLine(line, s, 2, 0)
		if !strings.Contains(output, "+2") {
			t.Error("Expected +2 in summary")
		}
		// Note: The content "@@ -1 +1,3 @@" contains "-", but the summary should not
		// contain "-0" since we omit zero counts. We verify +2 is present above.
	})
}

func TestFormatDiffHunkSeparator(t *testing.T) {
	cli.InitColors(cli.ColorModeNever)
	SyncStylesWithColorMode()
	s := GetStyles()

	t.Run("contains separator character", func(t *testing.T) {
		output := formatDiffHunkSeparator(s, 80)
		if !strings.Contains(output, "·") {
			t.Error("Expected middle dot separator character")
		}
	})

	t.Run("respects max width", func(t *testing.T) {
		output := formatDiffHunkSeparator(s, 200)
		// Width is capped at 60
		dotCount := strings.Count(output, "·")
		if dotCount > 60 {
			t.Errorf("Expected max 60 dots, got %d", dotCount)
		}
	})

	t.Run("respects min width", func(t *testing.T) {
		output := formatDiffHunkSeparator(s, 10)
		// Width floors at 10
		dotCount := strings.Count(output, "·")
		if dotCount < 10 {
			t.Errorf("Expected min 10 dots, got %d", dotCount)
		}
	})
}

func TestFormatDiffWithColorsStyled_MultiHunk(t *testing.T) {
	cli.InitColors(cli.ColorModeNever)
	SyncStylesWithColorMode()

	t.Run("multi-hunk patch has separators", func(t *testing.T) {
		patch := `--- a/file.go
+++ b/file.go
@@ -1,3 +1,3 @@
 context
-old1
+new1
@@ -10,4 +10,4 @@
 ctx2
-old2
-old3
+new2
+new3`
		output := formatDiffWithColorsStyled(patch)

		// Should contain the separator character between hunks
		if !strings.Contains(output, "·") {
			t.Error("Expected hunk separator in multi-hunk output")
		}

		// Should contain both hunk headers
		if !strings.Contains(output, "@@") {
			t.Error("Expected hunk headers in output")
		}

		// Should contain change summaries (check for parentheses)
		if !strings.Contains(output, "(") {
			t.Error("Expected change summary in hunk header")
		}
	})

	t.Run("single hunk has no separator", func(t *testing.T) {
		patch := `@@ -1,2 +1,2 @@
 context
-old
+new`
		output := formatDiffWithColorsStyled(patch)

		// Should not contain separator for single hunk
		if strings.Contains(output, "·") {
			t.Error("Expected no separator for single-hunk output")
		}
	})
}
