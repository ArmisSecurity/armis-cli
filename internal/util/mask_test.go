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
		{
			name:           "Go-style := assignment",
			input:          `apiKey := "sk_live_abc123xyz789def"`,
			wantContains:   "apiKey",
			wantNotContain: "abc123xyz789",
		},
		{
			name:           "arrow => assignment",
			input:          `password => "supersecretpassword123"`,
			wantContains:   "password",
			wantNotContain: "supersecret",
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

// TestMaskSecretInLine_NoPrefixLeakage verifies that identifying secret prefixes
// are NOT leaked in masked output. This prevents attackers from identifying
// secret types from masked output.
func TestMaskSecretInLine_NoPrefixLeakage(t *testing.T) {
	tests := []struct {
		name              string
		input             string
		forbiddenPrefixes []string // prefixes that must NOT appear in output
	}{
		{
			name:              "JWT token prefix eyJ must not leak",
			input:             `token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"`,
			forbiddenPrefixes: []string{"eyJ"},
		},
		{
			name:              "GitHub token prefix ghp_ must not leak",
			input:             `auth_token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"`,
			forbiddenPrefixes: []string{"ghp_"},
		},
		{
			name:              "AWS key prefix AKIA must not leak",
			input:             `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`,
			forbiddenPrefixes: []string{"AKIA"},
		},
		{
			name:              "Stripe key prefix sk_live_ must not leak",
			input:             `api_key = "sk_live_51H7example123456789"`,
			forbiddenPrefixes: []string{"sk_live_"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := util.MaskSecretInLine(tt.input)

			// Verify forbidden prefixes are NOT in output
			for _, prefix := range tt.forbiddenPrefixes {
				if strings.Contains(result, prefix) {
					t.Errorf("MaskSecretInLine(%q) = %q, must NOT contain identifying prefix %q", tt.input, result, prefix)
				}
			}

			// Verify output contains masking pattern (asterisks with length range)
			if !strings.Contains(result, "********") {
				t.Errorf("MaskSecretInLine(%q) = %q, expected masking pattern with asterisks", tt.input, result)
			}
		})
	}
}

func TestMaskSecretInMultiLineString(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		wantContains   string // substring that should be present
		wantNotContain string // substring that should NOT be present (the secret)
	}{
		{
			name:           "empty string",
			input:          "",
			wantContains:   "",
			wantNotContain: "",
		},
		{
			name:           "single line with secret",
			input:          `api_key = "sk_live_abc123xyz789"`,
			wantContains:   "api_key",
			wantNotContain: "abc123xyz789",
		},
		{
			name: "multi-line patch with secret",
			input: `--- a/config.go
+++ b/config.go
@@ -1,3 +1,3 @@
-api_key = "sk_live_secret123456789"
+api_key = os.Getenv("API_KEY")`,
			wantContains:   "os.Getenv",
			wantNotContain: "secret123456789",
		},
		{
			name: "mixed content - only secrets masked",
			input: `line 1: regular code
password = "supersecretpassword123"
line 3: more code`,
			wantContains:   "line 3: more code",
			wantNotContain: "supersecretpassword123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := util.MaskSecretInMultiLineString(tt.input)

			if tt.wantContains != "" && !strings.Contains(result, tt.wantContains) {
				t.Errorf("MaskSecretInMultiLineString() = %q, want to contain %q", result, tt.wantContains)
			}

			if tt.wantNotContain != "" && strings.Contains(result, tt.wantNotContain) {
				t.Errorf("MaskSecretInMultiLineString() = %q, should NOT contain secret %q", result, tt.wantNotContain)
			}
		})
	}
}

func TestMaskSecretInMultiLineString_PreservesLineCount(t *testing.T) {
	input := "line1\nline2\nline3\nline4"
	result := util.MaskSecretInMultiLineString(input)

	inputLines := strings.Count(input, "\n") + 1
	resultLines := strings.Count(result, "\n") + 1

	if inputLines != resultLines {
		t.Errorf("Line count changed: input has %d lines, result has %d lines", inputLines, resultLines)
	}
}

func TestMaskSecretsInStringMap(t *testing.T) {
	tests := []struct {
		name           string
		input          map[string]string
		wantNil        bool
		wantNotContain string // secret that should NOT appear in any value
	}{
		{
			name:    "nil map",
			input:   nil,
			wantNil: true,
		},
		{
			name:    "empty map",
			input:   map[string]string{},
			wantNil: false,
		},
		{
			name: "map with secrets",
			input: map[string]string{
				"config.go": `api_key = "sk_live_secret123456789"`,
				"main.go":   `func main() { fmt.Println("hello") }`,
			},
			wantNotContain: "secret123456789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := util.MaskSecretsInStringMap(tt.input)

			if tt.wantNil {
				if result != nil {
					t.Errorf("MaskSecretsInStringMap() = %v, want nil", result)
				}
				return
			}

			if result == nil {
				t.Error("MaskSecretsInStringMap() returned nil, want non-nil")
				return
			}

			// Verify all keys are preserved
			for k := range tt.input {
				if _, ok := result[k]; !ok {
					t.Errorf("Key %q missing from result", k)
				}
			}

			// Verify secrets are masked in values
			if tt.wantNotContain != "" {
				for k, v := range result {
					if strings.Contains(v, tt.wantNotContain) {
						t.Errorf("Secret %q found in result[%q] = %q", tt.wantNotContain, k, v)
					}
				}
			}
		})
	}
}

func TestMaskSecretsInStringMap_DoesNotModifyOriginal(t *testing.T) {
	original := map[string]string{
		"config.go": `api_key = "sk_live_secret123456789"`,
	}
	originalValue := original["config.go"]

	_ = util.MaskSecretsInStringMap(original)

	// Verify original map was not modified
	if original["config.go"] != originalValue {
		t.Error("MaskSecretsInStringMap modified the original map")
	}
}
