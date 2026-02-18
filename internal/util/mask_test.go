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
			input:          `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`, // #nosec G101
			wantContains:   "AWS_ACCESS_KEY_ID",
			wantNotContain: "IOSFODNN7",
		},
		{
			name:           "token in config",
			input:          `auth_token: "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"`, // #nosec G101
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
			input:          `secret_hash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"`, // #nosec G101
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
			input:             `auth_token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"`, // #nosec G101
			forbiddenPrefixes: []string{"ghp_"},
		},
		{
			name:              "AWS key prefix AKIA must not leak",
			input:             `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`, // #nosec G101
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

func TestMaskSecretInLine_WellKnownPrefixes(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		wantNotContain string
	}{
		{
			name:           "OpenAI key prefix sk-proj",
			input:          `self.openai_key = "sk-proj-1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"`,
			wantNotContain: "sk-proj-1234567890",
		},
		{
			name:           "Google/Firebase API key AIzaSy",
			input:          `firebase_key = "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe"`, // #nosec G101
			wantNotContain: "AIzaSyDaGmWKa4JsXZ",
		},
		{
			name:           "SendGrid key SG.",
			input:          `SENDGRID_KEY = "SG.1234567890abcdefghijklmnopqr.stuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"`,
			wantNotContain: "SG.1234567890",
		},
		{
			name:           "Stripe publishable key pk_live",
			input:          `stripe_public = "pk_live_51H9X8YF2eZvKYlo2C8RzQ9mN4P3vT5aU6gW7hE8iF9jG0kH1lI2mJ3nK4oL5pM6"`,
			wantNotContain: "pk_live_51H9X8YF",
		},
		{
			name:           "Mailgun key-prefix",
			input:          `MAILGUN_KEY = "key-1234567890abcdefghijklmnopqrstuv"`, // #nosec G101
			wantNotContain: "key-1234567890",
		},
		{
			name:           "Twilio Account SID AC prefix",
			input:          `TWILIO_SID = "AC1234567890abcdefghijklmnopqrstuv"`,
			wantNotContain: "AC1234567890",
		},
		{
			name:           "Azure connection string",
			input:          `azure_key = "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=abcdefghij"`,
			wantNotContain: "DefaultEndpointsProtocol=https",
		},
		{
			name:           "Slack webhook URL",
			input:          `SLACK_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"`, // #nosec G101
			wantNotContain: "hooks.slack.com",
		},
		{
			name:           "MongoDB connection string",
			input:          `connection_string = "mongodb://admin:password123@production-db.example.com:27017/mydb"`,
			wantNotContain: "mongodb://admin:password",
		},
		{
			name:           "PostgreSQL connection string",
			input:          `postgres_conn = "postgresql://dbuser:SuperSecret123@db.example.com:5432/production_db"`, // #nosec G101
			wantNotContain: "postgresql://dbuser:SuperSecret",
		},
		{
			name:           "Sentry DSN URL",
			input:          `"dsn": "https://1234567890abcdef@o123456.ingest.sentry.io/1234567"`, // #nosec G101
			wantNotContain: "1234567890abcdef@",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := util.MaskSecretInLine(tt.input)
			if strings.Contains(result, tt.wantNotContain) {
				t.Errorf("MaskSecretInLine() = %q, should NOT contain %q", result, tt.wantNotContain)
			}
			// Verify masked placeholder is present
			if !strings.Contains(result, "********") {
				t.Errorf("MaskSecretInLine() = %q, expected masked placeholder", result)
			}
		})
	}
}

func TestMaskSecretInLine_ServiceSpecificPatterns(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		wantNotContain string
	}{
		{
			name:           "self.openai_key with object prefix",
			input:          `self.openai_key = "sk-secret-1234567890abcdef"`,
			wantNotContain: "sk-secret-1234",
		},
		{
			name:           "sendgrid_key assignment",
			input:          `sendgrid_key = "SG.abcdefghijklmnopqrstuvwx.1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456"`,
			wantNotContain: "SG.abcdefgh",
		},
		{
			name:           "firebase_api_key",
			input:          `firebase_api_key = "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe"`, // #nosec G101
			wantNotContain: "AIzaSyDaGmW",
		},
		{
			name:           "mailchimp_key",
			input:          `mailchimp_key = "1234567890abcdefghijklmnopqrstuv-us1"`,
			wantNotContain: "1234567890abcdef",
		},
		{
			name:           "algolia_api_key",
			input:          `algolia_api_key = "1234567890abcdefghijklmnopqrstuv"`, // #nosec G101
			wantNotContain: "1234567890abc",
		},
		{
			name:           "datadog_api_key",
			input:          `datadog_api_key = "1234567890abcdefghijklmnopqrstuv"`, // #nosec G101
			wantNotContain: "1234567890abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := util.MaskSecretInLine(tt.input)
			if strings.Contains(result, tt.wantNotContain) {
				t.Errorf("MaskSecretInLine() = %q, should NOT contain %q", result, tt.wantNotContain)
			}
		})
	}
}

func TestMaskSecretInLine_DictLiterals(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		wantNotContain string
		wantContains   string
	}{
		{
			name:           "quoted key dict literal",
			input:          `"api_key": "sk-1234567890abcdefghijklmnopqrstuvwxyz"`,
			wantNotContain: "sk-1234567890abc",
			wantContains:   `"api_key"`,
		},
		{
			name:           "JSON-style secret token",
			input:          `"auth_token": "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"`, // #nosec G101
			wantNotContain: "ghp_1234567890",
			wantContains:   `"auth_token"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := util.MaskSecretInLine(tt.input)
			if strings.Contains(result, tt.wantNotContain) {
				t.Errorf("MaskSecretInLine() = %q, should NOT contain %q", result, tt.wantNotContain)
			}
			if tt.wantContains != "" && !strings.Contains(result, tt.wantContains) {
				t.Errorf("MaskSecretInLine() = %q, should contain %q", result, tt.wantContains)
			}
		})
	}
}

func TestMaskSecretInLine_DoesNotMaskEnvVarCalls(t *testing.T) {
	// Note: The 10+ character minimum for values means short function names
	// like os.Getenv (9 chars) won't be masked, but longer ones like
	// os.environ.get (14 chars) may be masked as false positives.
	// This is an acceptable trade-off for catching unquoted secrets.
	tests := []struct {
		name        string
		input       string
		wantContain string
	}{
		{
			name:        "os.Getenv call preserved (under 10 chars)",
			input:       `api_key = os.Getenv("API_KEY")`,
			wantContain: `os.Getenv("API_KEY")`,
		},
		{
			name:        "getenv call preserved",
			input:       `key = getenv("SECRET")`,
			wantContain: `getenv("SECRET")`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := util.MaskSecretInLine(tt.input)
			if !strings.Contains(result, tt.wantContain) {
				t.Errorf("MaskSecretInLine() = %q, should contain %q (env var call should not be masked)", result, tt.wantContain)
			}
		})
	}
}

// TestMaskSecretInLine_TwilioSIDAlphanumeric verifies that Twilio Account SIDs
// with alphanumeric characters (not just hex) are properly masked.
func TestMaskSecretInLine_TwilioSIDAlphanumeric(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		wantNotContain string
	}{
		{
			name:           "Twilio SID with non-hex letters (g-z)",
			input:          `account_sid = "AC1234567890abcdefghijklmnopqrstuv"`, // #nosec G101
			wantNotContain: "AC1234567890",
		},
		{
			name:           "Twilio SID uppercase letters beyond F",
			input:          `TWILIO_SID = "ACabcdefGHIJKLMNOPQRSTUVWXYZ012345"`, // #nosec G101
			wantNotContain: "ACabcdefGHIJKL",
		},
		{
			name:           "Twilio SID in JSON",
			input:          `"accountSid": "AC0123456789ABCDEFghijklmnopqrstuv"`, // #nosec G101
			wantNotContain: "AC0123456789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := util.MaskSecretInLine(tt.input)
			if strings.Contains(result, tt.wantNotContain) {
				t.Errorf("MaskSecretInLine() = %q, should NOT contain %q", result, tt.wantNotContain)
			}
			if !strings.Contains(result, "********") {
				t.Errorf("MaskSecretInLine() = %q, expected masked placeholder", result)
			}
		})
	}
}

// TestMaskSecretInLine_GenericSkToken verifies that sk- tokens without
// the specific live/test/proj suffix are still masked.
func TestMaskSecretInLine_GenericSkToken(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		wantNotContain string
	}{
		{
			name:           "generic sk- token (no suffix)",
			input:          `key = "sk-1234567890abcdefghijklmnopqrstuvwxyz"`, // #nosec G101
			wantNotContain: "sk-1234567890",
		},
		{
			name:           "OpenAI token without proj/live/test",
			input:          `OPENAI_KEY = "sk-abcdefghijklmnopqrstuvwxyz012345"`, // #nosec G101
			wantNotContain: "sk-abcdefghij",
		},
		{
			name:           "sk- token in quoted value",
			input:          `"apiKey": "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"`, // #nosec G101
			wantNotContain: "sk-ABCDEFGHIJ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := util.MaskSecretInLine(tt.input)
			if strings.Contains(result, tt.wantNotContain) {
				t.Errorf("MaskSecretInLine() = %q, should NOT contain %q", result, tt.wantNotContain)
			}
			if !strings.Contains(result, "********") {
				t.Errorf("MaskSecretInLine() = %q, expected masked placeholder", result)
			}
		})
	}
}

// TestMaskSecretInLine_BearerToken verifies that Bearer tokens in
// Authorization headers are masked (without assignment operator).
func TestMaskSecretInLine_BearerToken(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		wantNotContain string
		wantContains   string
	}{
		{
			name:           "Bearer token in header string",
			input:          `"Bearer sk-1234567890abcdefghijklmnopqrstuvwxyz"`, // #nosec G101
			wantNotContain: "sk-1234567890",
		},
		{
			name:           "Bearer with single quotes",
			input:          `'Bearer ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD'`, // #nosec G101
			wantNotContain: "ghp_1234567890",
		},
		{
			name:           "Authorization header value",
			input:          `Authorization: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test"`, // #nosec G101
			wantNotContain: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			wantContains:   "Authorization",
		},
		{
			name:           "Bearer without quotes",
			input:          `Bearer sk-1234567890abcdefghijklmnopqrstuvwxyz`, // #nosec G101
			wantNotContain: "sk-1234567890",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := util.MaskSecretInLine(tt.input)
			if strings.Contains(result, tt.wantNotContain) {
				t.Errorf("MaskSecretInLine() = %q, should NOT contain %q", result, tt.wantNotContain)
			}
			if tt.wantContains != "" && !strings.Contains(result, tt.wantContains) {
				t.Errorf("MaskSecretInLine() = %q, should contain %q", result, tt.wantContains)
			}
			if !strings.Contains(result, "********") {
				t.Errorf("MaskSecretInLine() = %q, expected masked placeholder", result)
			}
		})
	}
}

// TestMaskSecretInLine_TokenPrefixValues verifies that values starting with
// token_ followed by alphanumeric are masked.
func TestMaskSecretInLine_TokenPrefixValues(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		wantNotContain string
	}{
		{
			name:           "X-Auth-Token header value",
			input:          `"X-Auth-Token": "token_1234567890abcdefghijklmnopqrstuvwxyz"`, // #nosec G101
			wantNotContain: "token_1234567890",
		},
		{
			name:           "token_ value without quotes",
			input:          `auth = token_abcdefghijklmnopqrstuvwxyz012345`, // #nosec G101
			wantNotContain: "token_abcdefghij",
		},
		{
			name:           "token_ in assignment",
			input:          `my_token = "token_ABCDEFGHIJKLMNOPQRSTUVWXYZ"`, // #nosec G101
			wantNotContain: "token_ABCDEFGHIJ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := util.MaskSecretInLine(tt.input)
			if strings.Contains(result, tt.wantNotContain) {
				t.Errorf("MaskSecretInLine() = %q, should NOT contain %q", result, tt.wantNotContain)
			}
			if !strings.Contains(result, "********") {
				t.Errorf("MaskSecretInLine() = %q, expected masked placeholder", result)
			}
		})
	}
}

// TestMaskSecretInLine_BareKeywordDictLiterals verifies that dict literals with
// bare keywords like "password" (not "db_password") are masked.
func TestMaskSecretInLine_BareKeywordDictLiterals(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		wantNotContain string
		wantContains   string
	}{
		{
			name:           "bare password key",
			input:          `"password": "SuperSecretPassword123!"`, // #nosec G101
			wantNotContain: "SuperSecretPassword",
			wantContains:   `"password"`,
		},
		{
			name:           "bare secret key",
			input:          `"secret": "my_super_secret_value_here"`, // #nosec G101
			wantNotContain: "my_super_secret",
			wantContains:   `"secret"`,
		},
		{
			name:           "bare token key",
			input:          `"token": "abcdefghijklmnopqrstuvwxyz"`, // #nosec G101
			wantNotContain: "abcdefghijklmnop",
			wantContains:   `"token"`,
		},
		{
			name:           "private_key_id field",
			input:          `"private_key_id": "1234567890abcdef1234567890abcdef12345678"`, // #nosec G101
			wantNotContain: "1234567890abcdef",
			wantContains:   `"private_key_id"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := util.MaskSecretInLine(tt.input)
			if strings.Contains(result, tt.wantNotContain) {
				t.Errorf("MaskSecretInLine() = %q, should NOT contain %q", result, tt.wantNotContain)
			}
			if tt.wantContains != "" && !strings.Contains(result, tt.wantContains) {
				t.Errorf("MaskSecretInLine() = %q, should contain %q", result, tt.wantContains)
			}
			if !strings.Contains(result, "********") {
				t.Errorf("MaskSecretInLine() = %q, expected masked placeholder", result)
			}
		})
	}
}

// TestMaskSecretInLine_PreservesQuotes verifies that well-known prefix patterns
// preserve surrounding quote structure when masking. This is a regression test
// for a bug where patterns like ['"]?(sk-...)['"]? replaced the entire match
// (including quotes) instead of just the captured value.
func TestMaskSecretInLine_PreservesQuotes(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantContain string // substring that MUST be present (to verify structure)
	}{
		{
			name:        "sk- token preserves double quotes",
			input:       `api_key = "sk-1234567890abcdefghijklmnopqrstuvwxyz"`,
			wantContain: `= "********`,
		},
		{
			name:        "sk- token preserves single quotes",
			input:       `api_key = 'sk-1234567890abcdefghijklmnopqrstuvwxyz'`,
			wantContain: `= '********`,
		},
		{
			name:        "GitHub PAT preserves quotes",
			input:       `token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"`, // #nosec G101
			wantContain: `= "********`,
		},
		{
			name:        "Slack webhook preserves quotes",
			input:       `WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"`, // #nosec G101
			wantContain: `= "********`,
		},
		{
			name:        "Bearer token preserves quotes and prefix",
			input:       `"Bearer sk-1234567890abcdefghijklmnopqrstuvwxyz"`,
			wantContain: `"Bearer ********`,
		},
		{
			name:        "MongoDB connection string preserves quotes",
			input:       `conn = "mongodb://admin:password123@db.example.com:27017/mydb"`, // #nosec G101
			wantContain: `= "********`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := util.MaskSecretInLine(tt.input)
			if !strings.Contains(result, tt.wantContain) {
				t.Errorf("MaskSecretInLine() = %q, should contain %q (quotes not preserved)", result, tt.wantContain)
			}
		})
	}
}

// TestMaskSecretInLine_PrivateKeys verifies that PEM-formatted private keys
// are properly masked, including RSA, EC, DSA, OPENSSH, and PGP variants.
func TestMaskSecretInLine_PrivateKeys(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		wantNotContain string
	}{
		{
			name: "RSA private key",
			input: `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyf8DgnX5X9g5yjW5tNk+PNqp
-----END RSA PRIVATE KEY-----`,
			wantNotContain: "MIIEowIBAAKCAQEA",
		},
		{
			name:           "EC private key inline",
			input:          `key = "-----BEGIN EC PRIVATE KEY-----MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEH-----END EC PRIVATE KEY-----"`, // #nosec G101
			wantNotContain: "MIGHAgEAMBMG",
		},
		{
			name:           "Generic private key",
			input:          `-----BEGIN PRIVATE KEY-----MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSk-----END PRIVATE KEY-----`,
			wantNotContain: "MIIEvgIBADAN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := util.MaskSecretInLine(tt.input)
			if strings.Contains(result, tt.wantNotContain) {
				t.Errorf("MaskSecretInLine() = %q, should NOT contain %q", result, tt.wantNotContain)
			}
			if !strings.Contains(result, "********") {
				t.Errorf("MaskSecretInLine() = %q, expected masked placeholder", result)
			}
		})
	}
}

// Benchmark tests to measure performance impact of secret masking patterns.
// Run with: go test -bench=. -benchmem ./internal/util/...

func BenchmarkMaskSecretInLine_NoSecrets(b *testing.B) {
	line := `func main() { fmt.Println("hello world") }`
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		util.MaskSecretInLine(line)
	}
}

func BenchmarkMaskSecretInLine_WithSecret(b *testing.B) {
	line := `api_key = "sk-1234567890abcdefghijklmnopqrstuvwxyz"` // #nosec G101
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		util.MaskSecretInLine(line)
	}
}

func BenchmarkMaskSecretInLine_MultipleSecrets(b *testing.B) {
	line := `config = { "api_key": "sk-1234567890abcdef", "token": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" }` // #nosec G101
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		util.MaskSecretInLine(line)
	}
}

func BenchmarkMaskSecretInMultiLineString(b *testing.B) {
	content := `package main

func main() {
    apiKey := "sk-1234567890abcdefghijklmnopqrstuvwxyz"
    password := "supersecretpassword123"
    token := "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    fmt.Println("Hello, World!")
}
` // #nosec G101
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		util.MaskSecretInMultiLineString(content)
	}
}
