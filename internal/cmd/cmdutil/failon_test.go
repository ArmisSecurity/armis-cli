package cmdutil

import (
	"strings"
	"testing"
)

func TestValidateFailOn(t *testing.T) {
	tests := []struct {
		name       string
		severities []string
		wantErr    bool
	}{
		{
			name:       "valid single severity",
			severities: []string{"CRITICAL"},
			wantErr:    false,
		},
		{
			name:       "valid multiple severities",
			severities: []string{"HIGH", "CRITICAL"},
			wantErr:    false,
		},
		{
			name:       "valid all severities",
			severities: []string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"},
			wantErr:    false,
		},
		{
			name:       "valid severity lowercase",
			severities: []string{"high"},
			wantErr:    false,
		},
		{
			name:       "invalid severity unknown",
			severities: []string{"INVALID"},
			wantErr:    true,
		},
		{
			name:       "invalid mixed valid and invalid",
			severities: []string{"HIGH", "invalid"},
			wantErr:    true,
		},
		{
			name:       "empty slice is valid",
			severities: []string{},
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFailOn(tt.severities)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFailOn(%v) error = %v, wantErr %v", tt.severities, err, tt.wantErr)
			}
		})
	}
}

func TestGetFailOn(t *testing.T) {
	t.Run("returns normalized severities", func(t *testing.T) {
		// GetFailOn is pure: it validates and uppercase-normalizes the slice it is
		// given. A lowercase entry must come back uppercased so ShouldFail (which
		// matches the levels it returns exactly) can trip the CI gate.
		result, err := GetFailOn([]string{"high", "CRITICAL"})
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if len(result) != 2 || result[0] != "HIGH" || result[1] != "CRITICAL" {
			t.Errorf("Expected [HIGH CRITICAL], got %v", result)
		}
	})

	t.Run("returns error for invalid severity", func(t *testing.T) {
		if _, err := GetFailOn([]string{"invalid"}); err == nil {
			t.Error("Expected error for invalid severity")
		}
	})

	// A level gates on itself and every level above it, as `--fail-on HIGH`
	// in the AppSec UI's pipeline snippets means; a list counts from its
	// lowest level, and no level gates on nothing.
	t.Run("is a threshold", func(t *testing.T) {
		for _, tt := range []struct {
			in   []string
			want string
		}{
			{[]string{"high"}, "HIGH,CRITICAL"},
			{[]string{"CRITICAL"}, "CRITICAL"},
			{[]string{"medium"}, "MEDIUM,HIGH,CRITICAL"},
			{[]string{"INFO"}, "INFO,LOW,MEDIUM,HIGH,CRITICAL"},
			{[]string{"CRITICAL", "LOW"}, "LOW,MEDIUM,HIGH,CRITICAL"},
			{[]string{"HIGH", "CRITICAL", "HIGH"}, "HIGH,CRITICAL"},
			{[]string{}, ""},
			{nil, ""},
		} {
			got, err := GetFailOn(tt.in)
			if err != nil || strings.Join(got, ",") != tt.want {
				t.Errorf("GetFailOn(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
			}
		}
	})
}

func TestValidateMinSeverity(t *testing.T) {
	tests := []struct {
		name     string
		severity string
		want     string
		wantErr  bool
	}{
		{name: "empty means no filter", severity: "", want: ""},
		{name: "uppercase", severity: "HIGH", want: "HIGH"},
		{name: "lowercase normalized", severity: "medium", want: "MEDIUM"},
		{name: "lowest level", severity: "info", want: "INFO"},
		{name: "typo", severity: "HIGHT", wantErr: true},
		{name: "comma list rejected", severity: "HIGH,CRITICAL", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateMinSeverity(tt.severity)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateMinSeverity(%q) error = %v, wantErr %v", tt.severity, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ValidateMinSeverity(%q) = %q, want %q", tt.severity, got, tt.want)
			}
		})
	}
}
