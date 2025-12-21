package repo

import (
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

func TestNewScanner(t *testing.T) {
	scanner := NewScanner(nil, true, "tenant-456", 50, true, 10*time.Minute, false)

	if scanner.noProgress != true {
		t.Error("Expected noProgress to be true")
	}
	if scanner.tenantID != "tenant-456" {
		t.Errorf("Expected tenantID 'tenant-456', got %s", scanner.tenantID)
	}
	if scanner.pageLimit != 50 {
		t.Errorf("Expected pageLimit 50, got %d", scanner.pageLimit)
	}
	if scanner.includeTests != true {
		t.Error("Expected includeTests to be true")
	}
	if scanner.timeout != 10*time.Minute {
		t.Errorf("Expected timeout 10m, got %v", scanner.timeout)
	}
	if scanner.includeNonExploitable != false {
		t.Error("Expected includeNonExploitable to be false")
	}
}

func TestIsTestFile(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		expected bool
	}{
		{
			name:     "go test file",
			filename: "main_test.go",
			expected: true,
		},
		{
			name:     "python test file with test_ prefix",
			filename: "test_main.py",
			expected: true,
		},
		{
			name:     "python test file with _test suffix",
			filename: "main_test.py",
			expected: true,
		},
		{
			name:     "javascript test file",
			filename: "main.test.js",
			expected: true,
		},
		{
			name:     "javascript spec file",
			filename: "main.spec.js",
			expected: true,
		},
		{
			name:     "typescript test file",
			filename: "main.test.ts",
			expected: true,
		},
		{
			name:     "typescript spec file",
			filename: "main.spec.ts",
			expected: true,
		},
		{
			name:     "java test file",
			filename: "MainTest.java",
			expected: true,
		},
		{
			name:     "java tests file",
			filename: "MainTests.java",
			expected: true,
		},
		{
			name:     "ruby spec file",
			filename: "main_spec.rb",
			expected: true,
		},
		{
			name:     "rust test file",
			filename: "main_test.rs",
			expected: true,
		},
		{
			name:     "vue test file",
			filename: "component.test.vue",
			expected: true,
		},
		{
			name:     "regular go file",
			filename: "main.go",
			expected: false,
		},
		{
			name:     "file with test in name but not test file",
			filename: "testament.go",
			expected: false,
		},
		{
			name:     "regular python file",
			filename: "main.py",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isTestFile(tt.filename)
			if result != tt.expected {
				t.Errorf("isTestFile(%q) = %v, want %v", tt.filename, result, tt.expected)
			}
		})
	}
}

func TestMapSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected model.Severity
	}{
		{"CRITICAL", model.SeverityCritical},
		{"critical", model.SeverityCritical},
		{"HIGH", model.SeverityHigh},
		{"high", model.SeverityHigh},
		{"MEDIUM", model.SeverityMedium},
		{"medium", model.SeverityMedium},
		{"LOW", model.SeverityLow},
		{"low", model.SeverityLow},
		{"INFO", model.SeverityInfo},
		{"UNKNOWN", model.SeverityInfo},
		{"", model.SeverityInfo},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := mapSeverity(tt.input)
			if result != tt.expected {
				t.Errorf("mapSeverity(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestCleanDescription(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "removes code location",
			input:    "Description\nCode_location - /path/to/file\nMore text",
			expected: "Description More text",
		},
		{
			name:     "removes code blob",
			input:    "Description\nCode Blob - some blob\nMore text",
			expected: "Description More text",
		},
		{
			name:     "removes confidence",
			input:    "Description\nConfidence - HIGH\nMore text",
			expected: "Description More text",
		},
		{
			name:     "removes empty lines",
			input:    "Line 1\n\n\nLine 2",
			expected: "Line 1 Line 2",
		},
		{
			name:     "simple description",
			input:    "Simple description",
			expected: "Simple description",
		},
		{
			name:     "empty description",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cleanDescription(tt.input)
			if result != tt.expected {
				t.Errorf("cleanDescription() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestShouldFilterByExploitability(t *testing.T) {
	tests := []struct {
		name     string
		labels   []model.Label
		expected bool
	}{
		{
			name: "scanner code match and not exploitable",
			labels: []model.Label{
				{Description: "scanner code", Value: "38295677"},
				{Description: "exploitable", Value: "false"},
			},
			expected: true,
		},
		{
			name: "scanner code match and exploitable 0",
			labels: []model.Label{
				{Description: "scanner code", Value: "38295677"},
				{Description: "exploitable", Value: "0"},
			},
			expected: true,
		},
		{
			name: "scanner code match but exploitable",
			labels: []model.Label{
				{Description: "scanner code", Value: "38295677"},
				{Description: "exploitable", Value: "true"},
			},
			expected: false,
		},
		{
			name: "no scanner code match",
			labels: []model.Label{
				{Description: "scanner code", Value: "12345"},
				{Description: "exploitable", Value: "false"},
			},
			expected: false,
		},
		{
			name: "case insensitive",
			labels: []model.Label{
				{Description: "Scanner Code", Value: "38295677"},
				{Description: "Exploitable", Value: "FALSE"},
			},
			expected: true,
		},
		{
			name:     "empty labels",
			labels:   []model.Label{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldFilterByExploitability(tt.labels)
			if result != tt.expected {
				t.Errorf("shouldFilterByExploitability() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsEmptyFinding(t *testing.T) {
	longDesc := "Long description"

	tests := []struct {
		name     string
		finding  model.NormalizedFinding
		expected bool
	}{
		{
			name: "has description",
			finding: model.NormalizedFinding{
				NormalizedRemediation: model.NormalizedRemediation{
					Description: "Some description",
				},
			},
			expected: false,
		},
		{
			name: "has long description markdown",
			finding: model.NormalizedFinding{
				NormalizedRemediation: model.NormalizedRemediation{
					VulnerabilityTypeMetadata: model.VulnerabilityTypeMetadata{
						LongDescriptionMarkdown: "# Markdown",
					},
				},
			},
			expected: false,
		},
		{
			name: "has task long description",
			finding: model.NormalizedFinding{
				NormalizedTask: model.NormalizedTask{
					LongDescription: &longDesc,
				},
			},
			expected: false,
		},
		{
			name: "has CVEs",
			finding: model.NormalizedFinding{
				NormalizedRemediation: model.NormalizedRemediation{
					VulnerabilityTypeMetadata: model.VulnerabilityTypeMetadata{
						CVEs: []string{"CVE-2023-1234"},
					},
				},
			},
			expected: false,
		},
		{
			name: "has CWEs",
			finding: model.NormalizedFinding{
				NormalizedRemediation: model.NormalizedRemediation{
					VulnerabilityTypeMetadata: model.VulnerabilityTypeMetadata{
						CWEs: []string{"CWE-79"},
					},
				},
			},
			expected: false,
		},
		{
			name: "has category",
			finding: model.NormalizedFinding{
				NormalizedRemediation: model.NormalizedRemediation{
					FindingCategory: "vulnerability",
				},
			},
			expected: false,
		},
		{
			name:     "completely empty",
			finding:  model.NormalizedFinding{},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isEmptyFinding(tt.finding)
			if result != tt.expected {
				t.Errorf("isEmptyFinding() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestShouldSkipDir(t *testing.T) {
	tests := []struct {
		name     string
		dir      string
		expected bool
	}{
		{
			name:     "skip .git",
			dir:      ".git",
			expected: true,
		},
		{
			name:     "skip .svn",
			dir:      ".svn",
			expected: true,
		},
		{
			name:     "skip .hg",
			dir:      ".hg",
			expected: true,
		},
		{
			name:     "regular directory",
			dir:      "src",
			expected: false,
		},
		{
			name:     "node_modules not skipped by shouldSkipDir",
			dir:      "node_modules",
			expected: false,
		},
		{
			name:     "vendor not skipped by shouldSkipDir",
			dir:      "vendor",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldSkipDir(tt.dir)
			if result != tt.expected {
				t.Errorf("shouldSkipDir(%q) = %v, want %v", tt.dir, result, tt.expected)
			}
		})
	}
}
