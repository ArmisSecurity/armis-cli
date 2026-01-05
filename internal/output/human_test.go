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
		case "CRITICAL":
			if len(group.Findings) != 1 {
				t.Errorf("Expected 1 CRITICAL finding, got %d", len(group.Findings))
			}
		case "HIGH":
			if len(group.Findings) != 2 {
				t.Errorf("Expected 2 HIGH findings, got %d", len(group.Findings))
			}
		case "MEDIUM":
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

	t.Run("handles absolute path", func(t *testing.T) {
		finding := model.Finding{
			File:      testFile,
			StartLine: 10,
			EndLine:   10,
		}

		snippet, _, err := loadSnippetFromFile("", finding)
		if err != nil {
			t.Fatalf("Expected no error with absolute path, got %v", err)
		}

		if !strings.Contains(snippet, "line 10") {
			t.Errorf("Expected snippet to contain target line 10")
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
