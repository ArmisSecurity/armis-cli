package util

import "testing"

func TestFormatCategory(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "CODE_VULNERABILITY",
			input:    "CODE_VULNERABILITY",
			expected: "Code Vulnerability",
		},
		{
			name:     "CODE_PACKAGE_VULNERABILITY",
			input:    "CODE_PACKAGE_VULNERABILITY",
			expected: "Code Package Vulnerability",
		},
		{
			name:     "INFRA_AS_CODE_MISCONFIGURATION",
			input:    "INFRA_AS_CODE_MISCONFIGURATION",
			expected: "Infra As Code Misconfiguration",
		},
		{
			name:     "single word",
			input:    "VULNERABILITY",
			expected: "Vulnerability",
		},
		{
			name:     "already lowercase",
			input:    "code_vulnerability",
			expected: "Code Vulnerability",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "mixed case",
			input:    "Code_Vulnerability",
			expected: "Code Vulnerability",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatCategory(tt.input)
			if result != tt.expected {
				t.Errorf("FormatCategory(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
