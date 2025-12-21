package output

import (
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

func TestGetFormatter(t *testing.T) {
	tests := []struct {
		name      string
		format    string
		wantErr   bool
		wantType  interface{}
	}{
		{
			name:     "human formatter",
			format:   "human",
			wantErr:  false,
			wantType: &HumanFormatter{},
		},
		{
			name:     "json formatter",
			format:   "json",
			wantErr:  false,
			wantType: &JSONFormatter{},
		},
		{
			name:     "sarif formatter",
			format:   "sarif",
			wantErr:  false,
			wantType: &SARIFFormatter{},
		},
		{
			name:     "junit formatter",
			format:   "junit",
			wantErr:  false,
			wantType: &JUnitFormatter{},
		},
		{
			name:    "unsupported formatter",
			format:  "xml",
			wantErr: true,
		},
		{
			name:    "empty format",
			format:  "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			formatter, err := GetFormatter(tt.format)
			if tt.wantErr {
				if err == nil {
					t.Errorf("GetFormatter(%q) expected error, got nil", tt.format)
				}
			} else {
				if err != nil {
					t.Errorf("GetFormatter(%q) unexpected error: %v", tt.format, err)
				}
				if formatter == nil {
					t.Errorf("GetFormatter(%q) returned nil formatter", tt.format)
				}
			}
		})
	}
}

func TestShouldFail(t *testing.T) {
	tests := []struct {
		name             string
		findings         []model.Finding
		failOnSeverities []string
		expected         bool
	}{
		{
			name:             "no findings",
			findings:         []model.Finding{},
			failOnSeverities: []string{"CRITICAL", "HIGH"},
			expected:         false,
		},
		{
			name: "has critical finding and should fail on critical",
			findings: []model.Finding{
				{Severity: model.SeverityCritical},
			},
			failOnSeverities: []string{"CRITICAL"},
			expected:         true,
		},
		{
			name: "has high finding but only fail on critical",
			findings: []model.Finding{
				{Severity: model.SeverityHigh},
			},
			failOnSeverities: []string{"CRITICAL"},
			expected:         false,
		},
		{
			name: "has multiple findings with one matching",
			findings: []model.Finding{
				{Severity: model.SeverityLow},
				{Severity: model.SeverityMedium},
				{Severity: model.SeverityHigh},
			},
			failOnSeverities: []string{"HIGH", "CRITICAL"},
			expected:         true,
		},
		{
			name: "no matching severities",
			findings: []model.Finding{
				{Severity: model.SeverityLow},
				{Severity: model.SeverityInfo},
			},
			failOnSeverities: []string{"CRITICAL", "HIGH"},
			expected:         false,
		},
		{
			name: "empty fail on severities",
			findings: []model.Finding{
				{Severity: model.SeverityCritical},
			},
			failOnSeverities: []string{},
			expected:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &model.ScanResult{
				Findings: tt.findings,
			}
			
			shouldFail := ShouldFail(result, tt.failOnSeverities)
			if shouldFail != tt.expected {
				t.Errorf("ShouldFail() = %v, want %v", shouldFail, tt.expected)
			}
		})
	}
}

func TestShouldFail_CaseSensitive(t *testing.T) {
	result := &model.ScanResult{
		Findings: []model.Finding{
			{Severity: model.SeverityHigh},
		},
	}

	if ShouldFail(result, []string{"high"}) {
		t.Error("ShouldFail should be case-sensitive and not match 'high' with 'HIGH'")
	}

	if !ShouldFail(result, []string{"HIGH"}) {
		t.Error("ShouldFail should match 'HIGH' with 'HIGH'")
	}
}
