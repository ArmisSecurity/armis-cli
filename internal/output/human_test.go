package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/model"
)

func TestGroupFindingsByCWE(t *testing.T) {
	findings := []model.Finding{
		{
			ID:       "1",
			Severity: model.SeverityHigh,
			CWEs:     []string{"CWE-79"},
			Title:    "XSS Vulnerability",
		},
		{
			ID:       "2",
			Severity: model.SeverityCritical,
			CWEs:     []string{"CWE-89"},
			Title:    "SQL Injection",
		},
		{
			ID:       "3",
			Severity: model.SeverityMedium,
			CWEs:     []string{"CWE-79"},
			Title:    "Another XSS",
		},
		{
			ID:       "4",
			Severity: model.SeverityLow,
			CWEs:     []string{},
			Title:    "No CWE",
		},
	}

	groups := groupFindings(findings, "cwe")

	if len(groups) != 3 {
		t.Errorf("Expected 3 groups, got %d", len(groups))
	}

	cwe79Count := 0
	cwe89Count := 0
	noCWECount := 0

	for _, group := range groups {
		switch group.Key {
		case "CWE-79":
			cwe79Count = len(group.Findings)
		case "CWE-89":
			cwe89Count = len(group.Findings)
		case "No CWE":
			noCWECount = len(group.Findings)
		}
	}

	if cwe79Count != 2 {
		t.Errorf("Expected 2 findings in CWE-79 group, got %d", cwe79Count)
	}
	if cwe89Count != 1 {
		t.Errorf("Expected 1 finding in CWE-89 group, got %d", cwe89Count)
	}
	if noCWECount != 1 {
		t.Errorf("Expected 1 finding in No CWE group, got %d", noCWECount)
	}
}

func TestGroupFindingsBySeverity(t *testing.T) {
	findings := []model.Finding{
		{ID: "1", Severity: model.SeverityHigh, Title: "High 1"},
		{ID: "2", Severity: model.SeverityCritical, Title: "Critical 1"},
		{ID: "3", Severity: model.SeverityHigh, Title: "High 2"},
		{ID: "4", Severity: model.SeverityMedium, Title: "Medium 1"},
	}

	groups := groupFindings(findings, "severity")

	if len(groups) != 3 {
		t.Errorf("Expected 3 groups, got %d", len(groups))
	}

	for _, group := range groups {
		switch group.Key {
		case string(model.SeverityCritical):
			if len(group.Findings) != 1 {
				t.Errorf("Expected 1 CRITICAL finding, got %d", len(group.Findings))
			}
		case string(model.SeverityHigh):
			if len(group.Findings) != 2 {
				t.Errorf("Expected 2 HIGH findings, got %d", len(group.Findings))
			}
		case string(model.SeverityMedium):
			if len(group.Findings) != 1 {
				t.Errorf("Expected 1 MEDIUM finding, got %d", len(group.Findings))
			}
		}
	}
}

func TestGroupFindingsByFile(t *testing.T) {
	findings := []model.Finding{
		{ID: "1", File: testFileMainGo, Title: "Issue 1"},
		{ID: "2", File: testFileMainGo, Title: "Issue 2"},
		{ID: "3", File: "util.go", Title: "Issue 3"},
		{ID: "4", File: "", Title: "No file"},
	}

	groups := groupFindings(findings, "file")

	if len(groups) != 3 {
		t.Errorf("Expected 3 groups, got %d", len(groups))
	}

	for _, group := range groups {
		switch group.Key {
		case testFileMainGo:
			if len(group.Findings) != 2 {
				t.Errorf("Expected 2 findings in %s, got %d", testFileMainGo, len(group.Findings))
			}
		case "util.go":
			if len(group.Findings) != 1 {
				t.Errorf("Expected 1 finding in util.go, got %d", len(group.Findings))
			}
		case "Unknown File":
			if len(group.Findings) != 1 {
				t.Errorf("Expected 1 finding in Unknown File, got %d", len(group.Findings))
			}
		}
	}
}

func TestMaskEmail(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"john.doe@example.com", "j***@e***.com"},
		{"a@b.com", "a***@b***.com"},
		{"test@subdomain.example.org", "t***@s***.org"},
		{"", ""},
		{"invalid", "invalid"},
	}

	for _, tt := range tests {
		result := maskEmail(tt.input)
		if result != tt.expected {
			t.Errorf("maskEmail(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		severity model.Severity
		expected int
	}{
		{model.SeverityCritical, 0},
		{model.SeverityHigh, 1},
		{model.SeverityMedium, 2},
		{model.SeverityLow, 3},
		{model.SeverityInfo, 4},
	}

	for _, tt := range tests {
		result := severityRank(tt.severity)
		if result != tt.expected {
			t.Errorf("severityRank(%v) = %d, want %d", tt.severity, result, tt.expected)
		}
	}
}

func TestParseGitBlame(t *testing.T) {
	output := `abc123def456 1 1 1
author John Doe
author-mail <john.doe@example.com>
author-time 1700000000
author-tz +0000
committer John Doe
committer-mail <john.doe@example.com>
committer-time 1700000000
committer-tz +0000
summary Initial commit
filename test.go
        fmt.Println("test")`

	info := parseGitBlame(output)

	if info == nil {
		t.Fatal("Expected non-nil GitBlameInfo")
		return
	}

	if info.Author != "John Doe" {
		t.Errorf("Expected author 'John Doe', got %q", info.Author)
	}

	if info.Email != "john.doe@example.com" {
		t.Errorf("Expected email 'john.doe@example.com', got %q", info.Email)
	}

	if info.CommitSHA != "abc123def456" {
		t.Errorf("Expected commit 'abc123def456', got %q", info.CommitSHA)
	}
}

func TestGetTopLevelDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "com"},
		{"subdomain.example.org", "org"},
		{"test.co.uk", "uk"},
		{"localhost", "localhost"},
	}

	for _, tt := range tests {
		result := getTopLevelDomain(tt.input)
		if result != tt.expected {
			t.Errorf("getTopLevelDomain(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestGetHumanDisplayTitle(t *testing.T) {
	tests := []struct {
		name     string
		finding  model.Finding
		expected string
	}{
		{
			name: "OWASP title with CWE - strips CWE suffix",
			finding: model.Finding{
				Title: "Injection (CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection'))",
			},
			expected: "Injection",
		},
		{
			name: "OWASP title with CWE - Broken Access Control",
			finding: model.Finding{
				Title: "Broken Access Control (CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal'))",
			},
			expected: "Broken Access Control",
		},
		{
			name: "Simple title without CWE - unchanged",
			finding: model.Finding{
				Title: "Exposed Secret",
			},
			expected: "Exposed Secret",
		},
		{
			name: "CVE title - unchanged",
			finding: model.Finding{
				Title: "CVE-2023-1234 (+2 more)",
			},
			expected: "CVE-2023-1234 (+2 more)",
		},
		{
			name: "Title with parentheses but not CWE - unchanged",
			finding: model.Finding{
				Title: "SQL Injection (parametric query)",
			},
			expected: "SQL Injection (parametric query)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getHumanDisplayTitle(tt.finding)
			if result != tt.expected {
				t.Errorf("getHumanDisplayTitle() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestWrapTitle(t *testing.T) {
	tests := []struct {
		name     string
		title    string
		maxWidth int
		indent   int
		expected string
	}{
		{
			name:     "short title - no wrapping needed",
			title:    "SQL Injection vulnerability",
			maxWidth: 80,
			indent:   10,
			expected: "SQL Injection vulnerability",
		},
		{
			name:     "exact fit - no wrapping",
			title:    "Short title",
			maxWidth: 11,
			indent:   5,
			expected: "Short title",
		},
		{
			name:     "wraps to two lines",
			title:    "In the FindingsBigNumbers component line 22 calls capabilities.hasCapability without null checking",
			maxWidth: 60,
			indent:   10,
			expected: "In the FindingsBigNumbers component line 22 calls\n          capabilities.hasCapability without null checking",
		},
		{
			name:     "wraps to multiple lines",
			title:    "one two three four five six seven eight nine ten",
			maxWidth: 15,
			indent:   4,
			expected: "one two three\n    four five six\n    seven eight\n    nine ten",
		},
		{
			name:     "empty title",
			title:    "",
			maxWidth: 80,
			indent:   10,
			expected: "",
		},
		{
			name:     "zero maxWidth returns original",
			title:    "Test title",
			maxWidth: 0,
			indent:   5,
			expected: "Test title",
		},
		{
			name:     "single long word - no good break point",
			title:    "VeryLongSingleWordThatCannotBeBroken more words here",
			maxWidth: 30,
			indent:   5,
			expected: "VeryLongSingleWordThatCannotBeBroken\n     more words here",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := wrapTitle(tt.title, tt.maxWidth, tt.indent)
			if result != tt.expected {
				t.Errorf("wrapTitle() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestLoadSnippetFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.go")

	content := `package main

import "fmt"

func main() {
        fmt.Println("line 6")
        fmt.Println("line 7")
        fmt.Println("line 8")
        fmt.Println("line 9")
        fmt.Println("line 10")
        fmt.Println("line 11")
        fmt.Println("line 12")
        fmt.Println("line 13")
        fmt.Println("line 14")
        fmt.Println("line 15")
}
`
	if err := os.WriteFile(testFile, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	t.Run("loads snippet with context", func(t *testing.T) {
		finding := model.Finding{
			File:      "test.go",
			StartLine: 10,
			EndLine:   10,
		}

		snippet, snippetStart, err := loadSnippetFromFile(tmpDir, finding)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}

		if snippetStart != 6 {
			t.Errorf("Expected snippet to start at line 6, got %d", snippetStart)
		}

		lines := strings.Split(snippet, "\n")
		if len(lines) != 9 {
			t.Errorf("Expected 9 lines (4 before + 1 target + 4 after), got %d", len(lines))
		}

		if !strings.Contains(snippet, "line 10") {
			t.Errorf("Expected snippet to contain target line 10")
		}
	})

	t.Run("handles start of file", func(t *testing.T) {
		finding := model.Finding{
			File:      "test.go",
			StartLine: 2,
			EndLine:   2,
		}

		_, snippetStart, err := loadSnippetFromFile(tmpDir, finding)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}

		if snippetStart != 1 {
			t.Errorf("Expected snippet to start at line 1 (can't go below), got %d", snippetStart)
		}
	})

	t.Run("handles missing end line", func(t *testing.T) {
		finding := model.Finding{
			File:      "test.go",
			StartLine: 10,
			EndLine:   0,
		}

		snippet, snippetStart, err := loadSnippetFromFile(tmpDir, finding)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}

		if snippetStart != 6 {
			t.Errorf("Expected snippet to start at line 6, got %d", snippetStart)
		}

		lines := strings.Split(snippet, "\n")
		if len(lines) < 4 {
			t.Errorf("Expected at least 4 lines (default window), got %d", len(lines))
		}
	})

	t.Run("rejects absolute path without repository context", func(t *testing.T) {
		finding := model.Finding{
			File:      testFile, // testFile is an absolute path
			StartLine: 10,
			EndLine:   10,
		}

		_, _, err := loadSnippetFromFile("", finding)
		if err == nil {
			t.Fatal("Expected error for absolute path without repository context, got nil")
		}
		if !strings.Contains(err.Error(), "absolute path not allowed") {
			t.Errorf("Expected error to mention 'absolute path not allowed', got: %v", err)
		}
	})

	t.Run("returns error for missing file", func(t *testing.T) {
		finding := model.Finding{
			File:      "nonexistent.go",
			StartLine: 10,
			EndLine:   10,
		}

		_, _, err := loadSnippetFromFile(tmpDir, finding)
		if err == nil {
			t.Error("Expected error for missing file, got nil")
		}
	})
}

func TestHighlightColumns(t *testing.T) {
	// Test highlighting logic - in non-TTY environments lipgloss won't output ANSI codes,
	// so we test that the text structure is preserved correctly

	t.Run("single line with both columns", func(t *testing.T) {
		// startLine == endLine == currentLine
		// Column 7-11 is "world"
		result := highlightColumns("hello world test", 7, 11, 10, 10, 10)
		// Should contain the original text
		if !strings.Contains(result, "hello") {
			t.Error("Result should contain 'hello'")
		}
		if !strings.Contains(result, "world") {
			t.Error("Result should contain 'world'")
		}
		if !strings.Contains(result, "test") {
			t.Error("Result should contain 'test'")
		}
	})

	t.Run("start column exceeds line length on single line", func(t *testing.T) {
		result := highlightColumns("short", 100, 105, 10, 10, 10)
		// Should highlight entire line when columns exceed bounds
		if !strings.Contains(result, "short") {
			t.Error("Result should contain 'short'")
		}
	})

	t.Run("end column exceeds line length on single line", func(t *testing.T) {
		result := highlightColumns("hello", 3, 100, 10, 10, 10)
		// "he" should be plain, "llo" should be highlighted
		if !strings.Contains(result, "he") {
			t.Error("Result should contain 'he'")
		}
		if !strings.Contains(result, "llo") {
			t.Error("Result should contain 'llo'")
		}
	})

	t.Run("start line only - highlights from column to end", func(t *testing.T) {
		// currentLine == startLine but startLine != endLine
		result := highlightColumns("start text here", 7, 10, 10, 10, 15)
		// "start " should be plain, "text here" should be highlighted
		if !strings.Contains(result, "start") {
			t.Error("Result should contain 'start'")
		}
		if !strings.Contains(result, "text here") {
			t.Error("Result should contain 'text here'")
		}
	})

	t.Run("middle line - highlights entire line", func(t *testing.T) {
		// currentLine is between startLine and endLine
		result := highlightColumns("middle content", 1, 10, 12, 10, 15)
		// Entire line should be highlighted
		if !strings.Contains(result, "middle content") {
			t.Error("Result should contain 'middle content'")
		}
	})

	t.Run("end line only - highlights from start to column", func(t *testing.T) {
		// currentLine == endLine but startLine != endLine
		result := highlightColumns("end text here", 1, 8, 15, 10, 15)
		// "end text" should be highlighted, " here" should be plain
		if !strings.Contains(result, "end text") {
			t.Error("Result should contain 'end text'")
		}
		if !strings.Contains(result, "here") {
			t.Error("Result should contain 'here'")
		}
	})
}

func TestScanDurationFormatting(t *testing.T) {
	t.Run("valid duration - seconds only", func(t *testing.T) {
		result := &model.ScanResult{
			StartedAt: "2024-01-15T10:00:00Z",
			EndedAt:   "2024-01-15T10:00:45Z",
		}
		duration := scanDuration(result)
		if duration != "45s" {
			t.Errorf("Expected '45s', got %q", duration)
		}
	})

	t.Run("valid duration - minutes and seconds", func(t *testing.T) {
		result := &model.ScanResult{
			StartedAt: "2024-01-15T10:00:00Z",
			EndedAt:   "2024-01-15T10:05:30Z",
		}
		duration := scanDuration(result)
		if duration != "5m30s" {
			t.Errorf("Expected '5m30s', got %q", duration)
		}
	})

	t.Run("valid duration - hours minutes seconds", func(t *testing.T) {
		result := &model.ScanResult{
			StartedAt: "2024-01-15T10:00:00Z",
			EndedAt:   "2024-01-15T12:30:45Z",
		}
		duration := scanDuration(result)
		if duration != "2h30m45s" {
			t.Errorf("Expected '2h30m45s', got %q", duration)
		}
	})

	t.Run("zero duration", func(t *testing.T) {
		result := &model.ScanResult{
			StartedAt: "2024-01-15T10:00:00Z",
			EndedAt:   "2024-01-15T10:00:00Z",
		}
		duration := scanDuration(result)
		if duration != "0s" {
			t.Errorf("Expected '0s', got %q", duration)
		}
	})
}

func TestGetGitBlame(t *testing.T) {
	t.Run("returns nil for non-git directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		result := getGitBlame(tmpDir, "test.go", 1, false)
		if result != nil {
			t.Error("Expected nil for non-git directory")
		}
	})

	t.Run("returns nil for invalid file path", func(t *testing.T) {
		tmpDir := t.TempDir()
		// Path traversal attempt
		result := getGitBlame(tmpDir, "../../../etc/passwd", 1, false)
		if result != nil {
			t.Error("Expected nil for invalid path")
		}
	})

	t.Run("returns nil for non-existent file in git repo", func(t *testing.T) {
		// Use the current directory (which should be in a git repo during tests)
		// This avoids hardcoding absolute paths that break on other machines/CI
		projectDir := "."
		result := getGitBlame(projectDir, "nonexistent_file_xyz.go", 1, false)
		if result != nil {
			t.Error("Expected nil for non-existent file")
		}
	})
}

func TestParseGitBlameEdgeCases(t *testing.T) {
	t.Run("empty output", func(t *testing.T) {
		result := parseGitBlame("")
		if result != nil {
			t.Error("Expected nil for empty output")
		}
	})

	t.Run("incomplete output - missing author", func(t *testing.T) {
		output := `abc123def456 1 1 1
author-mail <test@example.com>
author-time 1700000000`
		result := parseGitBlame(output)
		if result != nil {
			t.Error("Expected nil when author is missing")
		}
	})

	t.Run("invalid timestamp format", func(t *testing.T) {
		output := `abc123def456 1 1 1
author John Doe
author-mail <john@example.com>
author-time invalid-timestamp`
		result := parseGitBlame(output)
		if result == nil {
			t.Fatal("Expected non-nil result")
		}
		// Date should be the raw value when parsing fails
		if result.Date != "invalid-timestamp" {
			t.Errorf("Expected date to be 'invalid-timestamp', got %q", result.Date)
		}
	})
}

func TestWrapText(t *testing.T) {
	t.Run("wraps long text at word boundaries", func(t *testing.T) {
		text := "This is a long line of text that should be wrapped at word boundaries when it exceeds the specified width limit."
		result := wrapText(text, 40, "  ")

		lines := strings.Split(result, "\n")
		for _, line := range lines {
			if len(line) > 42 { // 40 + margin for edge cases
				t.Errorf("Line exceeds width: %q (len=%d)", line, len(line))
			}
		}
		if !strings.HasPrefix(result, "  ") {
			t.Error("Expected indent prefix")
		}
	})

	t.Run("preserves existing newlines", func(t *testing.T) {
		text := "Line one.\nLine two.\nLine three."
		result := wrapText(text, 80, "  ")

		if strings.Count(result, "\n") < 2 {
			t.Error("Expected at least 2 newlines to be preserved")
		}
	})

	t.Run("handles empty text", func(t *testing.T) {
		result := wrapText("", 80, "  ")
		if result != "  " {
			t.Errorf("Expected just indent for empty text, got %q", result)
		}
	})

	t.Run("uses default width when zero", func(t *testing.T) {
		text := "Short text"
		result := wrapText(text, 0, "  ")
		if !strings.HasPrefix(result, "  Short") {
			t.Errorf("Expected wrapped text with indent, got %q", result)
		}
	})
}

func TestWrapLine(t *testing.T) {
	t.Run("wraps at word boundaries", func(t *testing.T) {
		line := "word1 word2 word3 word4 word5"
		result := wrapLine(line, 20, "  ")

		// Should wrap but not break words
		if strings.Contains(result, "word1word2") {
			t.Error("Words should not be concatenated")
		}
	})

	t.Run("handles single long word", func(t *testing.T) {
		line := "superlongwordthatwillnotfit"
		result := wrapLine(line, 20, "  ")

		// Should still output the word even if it exceeds width
		if !strings.Contains(result, "superlongwordthatwillnotfit") {
			t.Error("Long word should still be included")
		}
	})
}

func TestFormatRecommendations(t *testing.T) {
	t.Run("parses numbered list", func(t *testing.T) {
		text := "1. First recommendation. 2. Second recommendation. 3. Third recommendation."
		result := formatRecommendations(text, "  ")

		// Should have multiple lines for multiple items
		lines := strings.Split(result, "\n")
		if len(lines) < 3 {
			t.Errorf("Expected at least 3 lines for 3 recommendations, got %d", len(lines))
		}

		// Each item should start with its number
		if !strings.Contains(result, "  1. ") {
			t.Error("Expected '  1. ' prefix for first recommendation")
		}
		if !strings.Contains(result, "  2. ") {
			t.Error("Expected '  2. ' prefix for second recommendation")
		}
	})

	t.Run("handles single recommendation without numbering", func(t *testing.T) {
		text := "Just a single recommendation without numbers."
		result := formatRecommendations(text, "  ")

		// Should return wrapped text without special list formatting
		if !strings.HasPrefix(result, "  ") {
			t.Error("Expected indent prefix")
		}
	})

	t.Run("handles empty text", func(t *testing.T) {
		result := formatRecommendations("", "  ")
		if result != "" {
			t.Errorf("Expected empty string for empty input, got %q", result)
		}
	})

	t.Run("handles parenthesis style numbering", func(t *testing.T) {
		text := "1) First item. 2) Second item."
		result := formatRecommendations(text, "  ")

		// Should parse both "1." and "1)" style
		if !strings.Contains(result, "1.") || !strings.Contains(result, "2.") {
			t.Error("Expected numbered list output")
		}
	})

	t.Run("preserves text before first numbered item", func(t *testing.T) {
		text := "We recommend the following: 1. First item. 2. Second item."
		result := formatRecommendations(text, "  ")

		// Should include the preamble text
		if !strings.Contains(result, "We recommend the following") {
			t.Errorf("Expected preamble text to be preserved, got %q", result)
		}
		// Should also have the numbered items
		if !strings.Contains(result, "1.") || !strings.Contains(result, "2.") {
			t.Error("Expected numbered list output")
		}
	})
}

func TestWrapTextWithFirstLinePrefix(t *testing.T) {
	t.Run("uses different prefix for first line", func(t *testing.T) {
		text := "This is a recommendation that spans multiple lines."
		result := wrapTextWithFirstLinePrefix(text, 40, "  1. ", "     ")

		lines := strings.Split(result, "\n")
		if len(lines) < 2 {
			t.Skip("Text too short to wrap at width 40")
		}

		if !strings.HasPrefix(lines[0], "  1. ") {
			t.Errorf("First line should start with '  1. ', got %q", lines[0])
		}
		if len(lines) > 1 && !strings.HasPrefix(lines[1], "     ") {
			t.Errorf("Continuation line should start with '     ', got %q", lines[1])
		}
	})
}

func TestFormatCodeSnippetWithFrame_RedactedSnippet(t *testing.T) {
	// Enable colors for syntax highlighting to work
	cli.InitColors(cli.ColorModeAlways)
	SyncColors()
	defer func() {
		cli.InitColors(cli.ColorModeNever)
		SyncColors()
	}()

	// Syntax highlighting inserts ANSI codes BETWEEN characters of the code text.
	// For redacted content, the text should appear as one contiguous block.
	// Check if the snippet text is broken up by escape sequences.
	hasSyntaxHighlighting := func(result, snippet string) bool {
		// If the plain snippet appears contiguously in the result, no syntax highlighting was applied
		return !strings.Contains(result, snippet)
	}

	tests := []struct {
		name          string
		codeSnippet   string
		file          string
		wantHighlight bool
	}{
		{
			name:          "CLI masked content should not be highlighted",
			codeSnippet:   "password = ********[20-40]",
			file:          "config.py",
			wantHighlight: false,
		},
		{
			name:          "backend redaction message should not be highlighted",
			codeSnippet:   "Code snippet is redacted as it contains secrets.",
			file:          "sql_injection.py",
			wantHighlight: false,
		},
		{
			name:          "normal code should be highlighted",
			codeSnippet:   "password = os.getenv('SECRET')",
			file:          "config.py",
			wantHighlight: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := model.Finding{
				File:        tt.file,
				CodeSnippet: tt.codeSnippet,
				StartLine:   1,
				EndLine:     1,
			}

			result := formatCodeSnippetWithFrame(finding)
			hasHighlight := hasSyntaxHighlighting(result, tt.codeSnippet)

			if tt.wantHighlight && !hasHighlight {
				t.Errorf("Expected syntax highlighting for normal code (snippet should be broken up by ANSI codes)")
			}
			if !tt.wantHighlight && hasHighlight {
				t.Errorf("Did not expect syntax highlighting for redacted content, but snippet was broken up")
			}
		})
	}
}
