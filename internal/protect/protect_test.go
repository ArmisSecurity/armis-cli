package protect

import (
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{"72h", 72 * time.Hour, false},
		{"3d", 3 * 24 * time.Hour, false},
		{"1w", 7 * 24 * time.Hour, false},
		{"30m", 30 * time.Minute, false},
		{"1.5d", 36 * time.Hour, false},
		{"", 0, true},
		{"abc", 0, true},
		{"xd", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseDuration(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDuration(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.expected {
				t.Errorf("ParseDuration(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestClassifySeverity(t *testing.T) {
	threshold := 72 * time.Hour
	tests := []struct {
		age      time.Duration
		expected model.Severity
	}{
		{1 * time.Hour, model.SeverityHigh},
		{12 * time.Hour, model.SeverityHigh},
		{23 * time.Hour, model.SeverityHigh},
		{25 * time.Hour, model.SeverityMedium},
		{48 * time.Hour, model.SeverityMedium},
		{71 * time.Hour, model.SeverityMedium},
	}

	for _, tt := range tests {
		t.Run(tt.age.String(), func(t *testing.T) {
			got := ClassifySeverity(tt.age, threshold)
			if got != tt.expected {
				t.Errorf("ClassifySeverity(%v, %v) = %v, want %v", tt.age, threshold, got, tt.expected)
			}
		})
	}
}

func TestPolicyIsExcluded(t *testing.T) {
	policy := Policy{
		Exclusions: []string{"@myorg/*", "typescript"},
	}

	tests := []struct {
		name     string
		excluded bool
	}{
		{"@myorg/utils", true},
		{"@myorg/core", true},
		{"typescript", true},
		{"express", false},
		{"@other/pkg", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := policy.IsExcluded(tt.name)
			if got != tt.excluded {
				t.Errorf("IsExcluded(%q) = %v, want %v", tt.name, got, tt.excluded)
			}
		})
	}
}

func TestFormatAge(t *testing.T) {
	tests := []struct {
		age      time.Duration
		expected string
	}{
		{2 * time.Hour, "2h"},
		{24 * time.Hour, "1d"},
		{36 * time.Hour, "1d12h"},
		{72 * time.Hour, "3d"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := formatAge(tt.age)
			if got != tt.expected {
				t.Errorf("formatAge(%v) = %q, want %q", tt.age, got, tt.expected)
			}
		})
	}
}
