package cmdutil

import "testing"

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
		// given. A lowercase entry must come back uppercased so ShouldFail (exact
		// match) can trip the CI gate.
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
}
