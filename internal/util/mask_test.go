package util_test

import (
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/util"
)

func TestMaskSecretInLine(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		wantContains   string // substring that should be present
		wantNotContain string // substring that should NOT be present (the secret)
	}{
		{
			name:           "api key with equals",
			input:          `api_key = "sk_live_abc123xyz789"`,
			wantContains:   "api_key",
			wantNotContain: "abc123xyz789",
		},
		{
			name:           "password with colon",
			input:          `password: mysupersecretpassword`,
			wantContains:   "password",
			wantNotContain: "supersecret",
		},
		{
			name:           "AWS access key",
			input:          `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`,
			wantContains:   "AWS_ACCESS_KEY_ID",
			wantNotContain: "IOSFODNN7",
		},
		{
			name:           "token in config",
			input:          `auth_token: "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"`,
			wantContains:   "auth_token",
			wantNotContain: "xxxxxxxxxxx",
		},
		{
			name:           "no secret - regular code",
			input:          `func main() { fmt.Println("hello") }`,
			wantContains:   `fmt.Println("hello")`,
			wantNotContain: "",
		},
		{
			name:           "empty line",
			input:          "",
			wantContains:   "",
			wantNotContain: "",
		},
		{
			name:           "connection string",
			input:          `conn_str = "Server=myserver;Database=mydb;User=admin;Password=secret123"`,
			wantContains:   "conn_str",
			wantNotContain: "secret123",
		},
		{
			name:           "bearer token",
			input:          `bearer = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"`,
			wantContains:   "bearer",
			wantNotContain: "dozjgNryP4J3jVmNHl0w5N",
		},
		{
			name:           "secret hex hash",
			input:          `secret_hash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"`,
			wantContains:   "secret_hash",
			wantNotContain: "e5f6a1b2c3d4e5f6a1b2c3d4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := util.MaskSecretInLine(tt.input)

			if tt.wantContains != "" && !strings.Contains(result, tt.wantContains) {
				t.Errorf("MaskSecretInLine(%q) = %q, want to contain %q", tt.input, result, tt.wantContains)
			}

			if tt.wantNotContain != "" && strings.Contains(result, tt.wantNotContain) {
				t.Errorf("MaskSecretInLine(%q) = %q, should NOT contain secret %q", tt.input, result, tt.wantNotContain)
			}

			// Verify masking adds asterisks when secrets are present
			if tt.wantNotContain != "" && !strings.Contains(result, "*") {
				t.Errorf("MaskSecretInLine(%q) = %q, expected asterisks for masking", tt.input, result)
			}
		})
	}
}

func TestMaskSecretInLine_PreservesStructure(t *testing.T) {
	// Test that code structure is preserved
	input := `const config = { api_key: "secret12345678", name: "test" }`
	result := util.MaskSecretInLine(input)

	// Should still have the structure
	if !strings.Contains(result, "const config") {
		t.Errorf("Structure not preserved: missing 'const config' in %q", result)
	}
	if !strings.Contains(result, `name: "test"`) {
		t.Errorf("Structure not preserved: missing 'name: \"test\"' in %q", result)
	}
	// Secret should be masked
	if strings.Contains(result, "secret12345678") {
		t.Errorf("Secret not masked in %q", result)
	}
}

func TestMaskSecretInLines(t *testing.T) {
	input := []string{
		"line 1: regular code",
		"api_key = secretvalue123",
		"line 3: more code",
	}

	result := util.MaskSecretInLines(input)

	if len(result) != len(input) {
		t.Errorf("MaskSecretInLines returned %d lines, want %d", len(result), len(input))
	}

	// First line unchanged
	if result[0] != input[0] {
		t.Errorf("Line 0 changed unexpectedly: got %q, want %q", result[0], input[0])
	}

	// Second line should be masked
	if strings.Contains(result[1], "secretvalue123") {
		t.Errorf("Secret not masked in line 1: %q", result[1])
	}

	// Third line unchanged
	if result[2] != input[2] {
		t.Errorf("Line 2 changed unexpectedly: got %q, want %q", result[2], input[2])
	}
}

func TestMaskSecretInLines_NilInput(t *testing.T) {
	result := util.MaskSecretInLines(nil)
	if result != nil {
		t.Errorf("MaskSecretInLines(nil) = %v, want nil", result)
	}
}

func TestMaskSecretInLines_EmptySlice(t *testing.T) {
	result := util.MaskSecretInLines([]string{})
	if len(result) != 0 {
		t.Errorf("MaskSecretInLines([]) = %v, want empty slice", result)
	}
}
