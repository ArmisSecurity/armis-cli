package image

import (
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

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
		{
			name:     "only filtered content",
			input:    "Code_location - /path\nCode Blob - blob",
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
		{
			name: "only scanner code",
			labels: []model.Label{
				{Description: "scanner code", Value: "38295677"},
			},
			expected: false,
		},
		{
			name: "only exploitable",
			labels: []model.Label{
				{Description: "exploitable", Value: "false"},
			},
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
		{
			name: "empty strings and nil",
			finding: model.NormalizedFinding{
				NormalizedRemediation: model.NormalizedRemediation{
					Description: "",
					VulnerabilityTypeMetadata: model.VulnerabilityTypeMetadata{
						CVEs: []string{},
						CWEs: []string{},
					},
				},
			},
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

func TestFormatElapsed(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		expected string
	}{
		{
			name:     "zero duration",
			duration: 0,
			expected: "0s",
		},
		{
			name:     "seconds only",
			duration: 45 * time.Second,
			expected: "45s",
		},
		{
			name:     "one minute",
			duration: 60 * time.Second,
			expected: "1m 0s",
		},
		{
			name:     "minutes and seconds",
			duration: 125 * time.Second,
			expected: "2m 5s",
		},
		{
			name:     "many minutes",
			duration: 10*time.Minute + 30*time.Second,
			expected: "10m 30s",
		},
		{
			name:     "rounds to nearest second",
			duration: 45*time.Second + 600*time.Millisecond,
			expected: "46s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatElapsed(tt.duration)
			if result != tt.expected {
				t.Errorf("formatElapsed(%v) = %q, want %q", tt.duration, result, tt.expected)
			}
		})
	}
}

func TestNewScanner(t *testing.T) {
	scanner := NewScanner(nil, true, "tenant-123", 100, false, 5*time.Minute, true)
	
	if scanner.noProgress != true {
		t.Error("Expected noProgress to be true")
	}
	if scanner.tenantID != "tenant-123" {
		t.Errorf("Expected tenantID 'tenant-123', got %s", scanner.tenantID)
	}
	if scanner.pageLimit != 100 {
		t.Errorf("Expected pageLimit 100, got %d", scanner.pageLimit)
	}
	if scanner.includeTests != false {
		t.Error("Expected includeTests to be false")
	}
	if scanner.timeout != 5*time.Minute {
		t.Errorf("Expected timeout 5m, got %v", scanner.timeout)
	}
	if scanner.includeNonExploitable != true {
		t.Error("Expected includeNonExploitable to be true")
	}
}

func TestIsDockerAvailable(t *testing.T) {
	result := isDockerAvailable()
	
	if result {
		t.Log("Docker is available on this system")
	} else {
		t.Log("Docker is not available on this system")
	}
}

func TestGetDockerCommand(t *testing.T) {
	cmd := getDockerCommand()
	
	if cmd != dockerBinary && cmd != podmanBinary {
		t.Errorf("Expected docker or podman, got %s", cmd)
	}
}

func TestValidateDockerCommand(t *testing.T) {
	tests := []struct {
		name    string
		cmd     string
		wantErr bool
	}{
		{
			name:    "docker command",
			cmd:     "docker",
			wantErr: false,
		},
		{
			name:    "podman command",
			cmd:     "podman",
			wantErr: false,
		},
		{
			name:    "invalid command",
			cmd:     "invalid",
			wantErr: true,
		},
		{
			name:    "empty command",
			cmd:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDockerCommand(tt.cmd)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateDockerCommand(%q) error = %v, wantErr %v", tt.cmd, err, tt.wantErr)
			}
		})
	}
}
