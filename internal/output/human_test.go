package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
		{ID: "1", File: "main.go", Title: "Issue 1"},
		{ID: "2", File: "main.go", Title: "Issue 2"},
		{ID: "3", File: "util.go", Title: "Issue 3"},
		{ID: "4", File: "", Title: "No file"},
	}

	groups := groupFindings(findings, "file")

	if len(groups) != 3 {
		t.Errorf("Expected 3 groups, got %d", len(groups))
	}

	for _, group := range groups {
		switch group.Key {
		case "main.go":
			if len(group.Findings) != 2 {
				t.Errorf("Expected 2 findings in main.go, got %d", len(group.Findings))
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

func TestFormatCodeSnippet(t *testing.T) {
	t.Run("formats snippet with line numbers", func(t *testing.T) {
		finding := model.Finding{
			File:             "main.go",
			CodeSnippet:      "package main\n\nfunc main() {}",
			SnippetStartLine: 1,
			StartLine:        3,
			EndLine:          3,
		}

		result := formatCodeSnippet(finding)

		if !strings.Contains(result, "```go") {
			t.Error("Expected Go language identifier in code block")
		}
		if !strings.Contains(result, "```") {
			t.Error("Expected closing code block marker")
		}
		if !strings.Contains(result, "1  ") {
			t.Error("Expected line number 1")
		}
	})

	t.Run("highlights target line without columns", func(t *testing.T) {
		// Save and restore color values
		origBgRed := colorBgRed
		origBold := colorBold
		origReset := colorReset
		defer func() {
			colorBgRed = origBgRed
			colorBold = origBold
			colorReset = origReset
		}()

		// Use test markers for colors
		colorBgRed = "[BG_RED]"
		colorBold = "[BOLD]"
		colorReset = "[RESET]"

		finding := model.Finding{
			File:             "test.py",
			CodeSnippet:      "line1\nline2\nline3",
			SnippetStartLine: 5,
			StartLine:        6,
			EndLine:          6,
		}

		result := formatCodeSnippet(finding)

		// Line 6 should be highlighted (it's the second line of the snippet starting at line 5)
		if !strings.Contains(result, "[BG_RED][BOLD]line2[RESET]") {
			t.Errorf("Expected line2 to be highlighted, got:\n%s", result)
		}
	})

	t.Run("highlights with columns on single line", func(t *testing.T) {
		origBgRed := colorBgRed
		origBold := colorBold
		origReset := colorReset
		defer func() {
			colorBgRed = origBgRed
			colorBold = origBold
			colorReset = origReset
		}()

		colorBgRed = "[H]"
		colorBold = ""
		colorReset = "[/H]"

		finding := model.Finding{
			File:             "test.go",
			CodeSnippet:      "func test() { vulnerable() }",
			SnippetStartLine: 10,
			StartLine:        10,
			EndLine:          10,
			StartColumn:      15,
			EndColumn:        26,
		}

		result := formatCodeSnippet(finding)

		// Should highlight "vulnerable()"
		if !strings.Contains(result, "[H]vulnerable()[/H]") {
			t.Errorf("Expected 'vulnerable()' to be highlighted, got:\n%s", result)
		}
	})

	t.Run("uses default start line when not provided", func(t *testing.T) {
		finding := model.Finding{
			File:             "test.go",
			CodeSnippet:      "code line",
			SnippetStartLine: 0,
			StartLine:        0,
			EndLine:          0,
		}

		result := formatCodeSnippet(finding)

		// Should start at line 1 when SnippetStartLine is 0
		if !strings.Contains(result, "   1  ") {
			t.Errorf("Expected line number starting at 1, got:\n%s", result)
		}
	})

	t.Run("detects python language", func(t *testing.T) {
		finding := model.Finding{
			File:        "script.py",
			CodeSnippet: "print('hello')",
		}

		result := formatCodeSnippet(finding)

		if !strings.Contains(result, "```python") {
			t.Error("Expected python language identifier")
		}
	})
}

func TestHighlightColumns(t *testing.T) {
	// Save and restore color values
	origBgRed := colorBgRed
	origBold := colorBold
	origReset := colorReset
	defer func() {
		colorBgRed = origBgRed
		colorBold = origBold
		colorReset = origReset
	}()

	colorBgRed = "[H]"
	colorBold = ""
	colorReset = "[/H]"

	t.Run("single line with both columns", func(t *testing.T) {
		// startLine == endLine == currentLine
		// Column 7-11 is "world" (endCol is exclusive in slice, so we use 11 to get "world")
		result := highlightColumns("hello world test", 7, 11, 10, 10, 10)
		expected := "hello [H]world[/H] test"
		if result != expected {
			t.Errorf("Expected %q, got %q", expected, result)
		}
	})

	t.Run("start column exceeds line length on single line", func(t *testing.T) {
		result := highlightColumns("short", 100, 105, 10, 10, 10)
		const fullLineHighlight = "[H]short[/H]"
		expected := fullLineHighlight
		if result != expected {
			t.Errorf("Expected full line highlighted, got %q", result)
		}
	})

	t.Run("end column exceeds line length on single line", func(t *testing.T) {
		result := highlightColumns("hello", 3, 100, 10, 10, 10)
		expected := "he[H]llo[/H]"
		if result != expected {
			t.Errorf("Expected %q, got %q", expected, result)
		}
	})

	t.Run("start line only - highlights from column to end", func(t *testing.T) {
		// currentLine == startLine but startLine != endLine
		result := highlightColumns("start text here", 7, 10, 10, 10, 15)
		expected := "start [H]text here[/H]"
		if result != expected {
			t.Errorf("Expected %q, got %q", expected, result)
		}
	})

	t.Run("start line with column exceeding length", func(t *testing.T) {
		result := highlightColumns("short", 100, 105, 10, 10, 15)
		const fullLineHighlight = "[H]short[/H]"
		expected := fullLineHighlight
		if result != expected {
			t.Errorf("Expected full line highlighted, got %q", result)
		}
	})

	t.Run("end line only - highlights from start to column", func(t *testing.T) {
		// currentLine == endLine but startLine != endLine
		result := highlightColumns("end text here", 1, 8, 15, 10, 15)
		expected := "[H]end text[/H] here"
		if result != expected {
			t.Errorf("Expected %q, got %q", expected, result)
		}
	})

	t.Run("end line with column exceeding length", func(t *testing.T) {
		result := highlightColumns("short", 1, 100, 15, 10, 15)
		const fullLineHighlight = "[H]short[/H]"
		expected := fullLineHighlight
		if result != expected {
			t.Errorf("Expected %q, got %q", expected, result)
		}
	})

	t.Run("middle line - highlights entire line", func(t *testing.T) {
		// currentLine is between startLine and endLine
		result := highlightColumns("middle content", 1, 10, 12, 10, 15)
		expected := "[H]middle content[/H]"
		if result != expected {
			t.Errorf("Expected entire line highlighted, got %q", result)
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
		// Use the actual project directory (which is a git repo)
		projectDir := "/Users/yiftach.cohen/conductor/workspaces/armis-cli/edinburgh"
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
