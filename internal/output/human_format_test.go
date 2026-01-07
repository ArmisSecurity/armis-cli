package output

import (
	"bytes"
	"strings"
	"testing"

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

func TestGetSeverityColor(t *testing.T) {
	tests := []struct {
		severity model.Severity
		expected string
	}{
		{model.SeverityCritical, colorRed},
		{model.SeverityHigh, colorOrange},
		{model.SeverityMedium, colorYellow},
		{model.SeverityLow, colorBlue},
		{model.SeverityInfo, colorGray},
		{model.Severity("UNKNOWN"), ""},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			result := getSeverityColor(tt.severity)
			if result != tt.expected {
				t.Errorf("getSeverityColor(%s) = %q, want %q", tt.severity, result, tt.expected)
			}
		})
	}
}

func TestGetSeverityIcon(t *testing.T) {
	tests := []struct {
		severity model.Severity
		expected string
	}{
		{model.SeverityCritical, "🔴"},
		{model.SeverityHigh, "🟠"},
		{model.SeverityMedium, "🟡"},
		{model.SeverityLow, "🔵"},
		{model.SeverityInfo, "⚪"},
		{model.Severity("UNKNOWN"), "•"},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			result := getSeverityIcon(tt.severity)
			if result != tt.expected {
				t.Errorf("getSeverityIcon(%s) = %q, want %q", tt.severity, result, tt.expected)
			}
		})
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

func TestDetectLanguage(t *testing.T) {
	tests := []struct {
		filename string
		expected string
	}{
		{"main.go", "go"},
		{"script.py", "python"},
		{"app.js", "javascript"},
		{"style.css", "css"},
		{"index.html", "html"},
		{"config.json", "json"},
		{"data.xml", "xml"},
		{"script.sh", "bash"},
		{"unknown.xyz", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			result := detectLanguage(tt.filename)
			if result != tt.expected {
				t.Errorf("detectLanguage(%s) = %q, want %q", tt.filename, result, tt.expected)
			}
		})
	}
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

func TestDisableColors(t *testing.T) {
	// Save original color values
	origReset := colorReset
	origRed := colorRed
	origOrange := colorOrange
	origYellow := colorYellow
	origBlue := colorBlue
	origGray := colorGray
	origBgRed := colorBgRed
	origBold := colorBold
	origUnderline := colorUnderline

	// Restore colors after test
	defer func() {
		colorReset = origReset
		colorRed = origRed
		colorOrange = origOrange
		colorYellow = origYellow
		colorBlue = origBlue
		colorGray = origGray
		colorBgRed = origBgRed
		colorBold = origBold
		colorUnderline = origUnderline
	}()

	// Call disableColors
	disableColors()

	// Verify all color variables are empty
	if colorReset != "" {
		t.Errorf("colorReset should be empty, got %q", colorReset)
	}
	if colorRed != "" {
		t.Errorf("colorRed should be empty, got %q", colorRed)
	}
	if colorOrange != "" {
		t.Errorf("colorOrange should be empty, got %q", colorOrange)
	}
	if colorYellow != "" {
		t.Errorf("colorYellow should be empty, got %q", colorYellow)
	}
	if colorBlue != "" {
		t.Errorf("colorBlue should be empty, got %q", colorBlue)
	}
	if colorGray != "" {
		t.Errorf("colorGray should be empty, got %q", colorGray)
	}
	if colorBgRed != "" {
		t.Errorf("colorBgRed should be empty, got %q", colorBgRed)
	}
	if colorBold != "" {
		t.Errorf("colorBold should be empty, got %q", colorBold)
	}
	if colorUnderline != "" {
		t.Errorf("colorUnderline should be empty, got %q", colorUnderline)
	}
}

func TestFormattedOutputWithoutColors(t *testing.T) {
	// Save original color values
	origReset := colorReset
	origRed := colorRed
	origOrange := colorOrange
	origYellow := colorYellow
	origBlue := colorBlue
	origGray := colorGray
	origBgRed := colorBgRed
	origBold := colorBold
	origUnderline := colorUnderline

	// Restore colors after test
	defer func() {
		colorReset = origReset
		colorRed = origRed
		colorOrange = origOrange
		colorYellow = origYellow
		colorBlue = origBlue
		colorGray = origGray
		colorBgRed = origBgRed
		colorBold = origBold
		colorUnderline = origUnderline
	}()

	// Disable colors
	disableColors()

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
