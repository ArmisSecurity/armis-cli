package repo

import (
	"testing"
)

func TestParseDirectiveLine(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		wantDir     *SuppressionDirective
		wantIsDir   bool
		wantWarning string
	}{
		// Empty and comment lines
		{
			name:    "empty line",
			line:    "",
			wantDir: nil, wantIsDir: false,
		},
		{
			name:    "whitespace only",
			line:    "   ",
			wantDir: nil, wantIsDir: false,
		},
		{
			name:    "comment line",
			line:    "# this is a comment",
			wantDir: nil, wantIsDir: false,
		},

		// CWE directives
		{
			name:      "cwe:798",
			line:      "cwe:798",
			wantDir:   &SuppressionDirective{Type: DirectiveCWE, Value: "798"},
			wantIsDir: true,
		},
		{
			name:      "cwe:798 with reason",
			line:      "cwe:798 -- Environment variables, not hardcoded",
			wantDir:   &SuppressionDirective{Type: DirectiveCWE, Value: "798", Reason: "Environment variables, not hardcoded"},
			wantIsDir: true,
		},
		{
			name:      "cwe:79",
			line:      "cwe:79",
			wantDir:   &SuppressionDirective{Type: DirectiveCWE, Value: "79"},
			wantIsDir: true,
		},
		{
			name:      "cwe:0079 leading zeros normalized",
			line:      "cwe:0079",
			wantDir:   &SuppressionDirective{Type: DirectiveCWE, Value: "79"},
			wantIsDir: true,
		},
		{
			name:        "cwe:abc invalid",
			line:        "cwe:abc",
			wantDir:     nil,
			wantIsDir:   false,
			wantWarning: `invalid cwe value "abc" ignored (must be a non-negative integer)`,
		},
		{
			name:        "cwe:-1 negative",
			line:        "cwe:-1",
			wantDir:     nil,
			wantIsDir:   false,
			wantWarning: `invalid cwe value "-1" ignored (must be a non-negative integer)`,
		},
		{
			name:        "cwe:0 zero",
			line:        "cwe:0",
			wantDir:     &SuppressionDirective{Type: DirectiveCWE, Value: "0"},
			wantIsDir:   true,
			wantWarning: "cwe:0 will never match any findings",
		},
		{
			name:        "cwe: empty value",
			line:        "cwe:",
			wantDir:     nil,
			wantIsDir:   false,
			wantWarning: "empty cwe directive ignored",
		},

		// Severity directives
		{
			name:      "severity:HIGH",
			line:      "severity:HIGH",
			wantDir:   &SuppressionDirective{Type: DirectiveSeverity, Value: "HIGH"},
			wantIsDir: true,
		},
		{
			name:      "severity:low case insensitive",
			line:      "severity:low",
			wantDir:   &SuppressionDirective{Type: DirectiveSeverity, Value: "LOW"},
			wantIsDir: true,
		},
		{
			name:      "severity:Critical mixed case",
			line:      "severity:Critical",
			wantDir:   &SuppressionDirective{Type: DirectiveSeverity, Value: "CRITICAL"},
			wantIsDir: true,
		},
		{
			name:      "severity:INFO",
			line:      "severity:INFO",
			wantDir:   &SuppressionDirective{Type: DirectiveSeverity, Value: "INFO"},
			wantIsDir: true,
		},
		{
			name:      "severity with reason",
			line:      "severity:LOW -- Team policy: only address MEDIUM+ findings",
			wantDir:   &SuppressionDirective{Type: DirectiveSeverity, Value: "LOW", Reason: "Team policy: only address MEDIUM+ findings"},
			wantIsDir: true,
		},
		{
			name:        "severity:UNKNOWN invalid",
			line:        "severity:UNKNOWN",
			wantDir:     nil,
			wantIsDir:   false,
			wantWarning: `unknown severity "UNKNOWN" ignored (valid: CRITICAL, HIGH, MEDIUM, LOW, INFO)`,
		},
		{
			name:        "severity:BOGUS invalid",
			line:        "severity:BOGUS",
			wantDir:     nil,
			wantIsDir:   false,
			wantWarning: `unknown severity "BOGUS" ignored (valid: CRITICAL, HIGH, MEDIUM, LOW, INFO)`,
		},

		// Category directives
		{
			name:      "category:secrets",
			line:      "category:secrets",
			wantDir:   &SuppressionDirective{Type: DirectiveCategory, Value: "secrets"},
			wantIsDir: true,
		},
		{
			name:      "category:SAST case insensitive",
			line:      "category:SAST",
			wantDir:   &SuppressionDirective{Type: DirectiveCategory, Value: "sast"},
			wantIsDir: true,
		},
		{
			name:      "category:iac",
			line:      "category:iac",
			wantDir:   &SuppressionDirective{Type: DirectiveCategory, Value: "iac"},
			wantIsDir: true,
		},
		{
			name:      "category:sca",
			line:      "category:sca",
			wantDir:   &SuppressionDirective{Type: DirectiveCategory, Value: "sca"},
			wantIsDir: true,
		},
		{
			name:      "category:license",
			line:      "category:license",
			wantDir:   &SuppressionDirective{Type: DirectiveCategory, Value: "license"},
			wantIsDir: true,
		},
		{
			name:      "category with reason",
			line:      "category:secrets -- We use HashiCorp Vault",
			wantDir:   &SuppressionDirective{Type: DirectiveCategory, Value: "secrets", Reason: "We use HashiCorp Vault"},
			wantIsDir: true,
		},
		{
			name:        "category:invalid unknown",
			line:        "category:invalid",
			wantDir:     nil,
			wantIsDir:   false,
			wantWarning: `unknown category "invalid" ignored (valid: sast, secrets, iac, sca, license)`,
		},

		// Rule directives
		{
			name:      "rule:CKV_AWS_18",
			line:      "rule:CKV_AWS_18",
			wantDir:   &SuppressionDirective{Type: DirectiveRule, Value: "CKV_AWS_18"},
			wantIsDir: true,
		},
		{
			name:      "rule with dots",
			line:      "rule:python.lang.security.audit.subprocess-shell-true",
			wantDir:   &SuppressionDirective{Type: DirectiveRule, Value: "python.lang.security.audit.subprocess-shell-true"},
			wantIsDir: true,
		},
		{
			name:      "rule with reason",
			line:      "rule:CKV_DOCKER_3 -- Required for our build pipeline",
			wantDir:   &SuppressionDirective{Type: DirectiveRule, Value: "CKV_DOCKER_3", Reason: "Required for our build pipeline"},
			wantIsDir: true,
		},
		{
			name:        "rule: empty value",
			line:        "rule:",
			wantDir:     nil,
			wantIsDir:   false,
			wantWarning: `empty rule directive ignored: "rule:"`,
		},

		// Path patterns (not directives)
		{
			name:    "vendor/ path pattern",
			line:    "vendor/",
			wantDir: nil, wantIsDir: false,
		},
		{
			name:    "*.min.js path pattern",
			line:    "*.min.js",
			wantDir: nil, wantIsDir: false,
		},
		{
			name:    "generated/**/*.go path pattern",
			line:    "generated/**/*.go",
			wantDir: nil, wantIsDir: false,
		},
		{
			name:    "invalid:directive treated as path",
			line:    "invalid:directive",
			wantDir: nil, wantIsDir: false,
		},
		{
			name:    "docs/ path pattern",
			line:    "docs/",
			wantDir: nil, wantIsDir: false,
		},

		// Whitespace handling
		{
			name:      "leading whitespace",
			line:      "  cwe:798",
			wantDir:   &SuppressionDirective{Type: DirectiveCWE, Value: "798"},
			wantIsDir: true,
		},
		{
			name:      "trailing whitespace",
			line:      "cwe:798  ",
			wantDir:   &SuppressionDirective{Type: DirectiveCWE, Value: "798"},
			wantIsDir: true,
		},
		{
			name:      "whitespace around value",
			line:      "  severity:HIGH  ",
			wantDir:   &SuppressionDirective{Type: DirectiveSeverity, Value: "HIGH"},
			wantIsDir: true,
		},

		// Reason delimiter edge cases
		{
			name:      "reason with -- in text",
			line:      "cwe:798 -- reason -- with dashes",
			wantDir:   &SuppressionDirective{Type: DirectiveCWE, Value: "798", Reason: "reason -- with dashes"},
			wantIsDir: true,
		},
		{
			name:        "no space before -- not a delimiter",
			line:        "cwe:798-- not a reason",
			wantDir:     nil,
			wantIsDir:   false,
			wantWarning: `invalid cwe value "798-- not a reason" ignored (must be a non-negative integer)`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, isDir, warning := parseDirectiveLine(tt.line)

			if isDir != tt.wantIsDir {
				t.Errorf("isDirective = %v, want %v", isDir, tt.wantIsDir)
			}

			if tt.wantDir == nil {
				if dir != nil {
					t.Errorf("directive = %+v, want nil", dir)
				}
			} else {
				if dir == nil {
					t.Fatalf("directive = nil, want %+v", tt.wantDir)
				}
				if dir.Type != tt.wantDir.Type {
					t.Errorf("Type = %q, want %q", dir.Type, tt.wantDir.Type)
				}
				if dir.Value != tt.wantDir.Value {
					t.Errorf("Value = %q, want %q", dir.Value, tt.wantDir.Value)
				}
				if dir.Reason != tt.wantDir.Reason {
					t.Errorf("Reason = %q, want %q", dir.Reason, tt.wantDir.Reason)
				}
			}

			if tt.wantWarning != "" {
				if warning != tt.wantWarning {
					t.Errorf("warning = %q, want %q", warning, tt.wantWarning)
				}
			} else if warning != "" {
				t.Errorf("unexpected warning: %q", warning)
			}
		})
	}
}

func TestSuppressionConfig_Add(t *testing.T) {
	config := NewSuppressionConfig()

	config.Add(SuppressionDirective{Type: DirectiveRule, Value: "CKV_AWS_18"})
	config.Add(SuppressionDirective{Type: DirectiveCategory, Value: "secrets"})
	config.Add(SuppressionDirective{Type: DirectiveSeverity, Value: "LOW"})
	config.Add(SuppressionDirective{Type: DirectiveCWE, Value: "798"})
	config.Add(SuppressionDirective{Type: DirectiveCWE, Value: "79"})

	if len(config.Rules) != 1 {
		t.Errorf("Rules count = %d, want 1", len(config.Rules))
	}
	if len(config.Categories) != 1 {
		t.Errorf("Categories count = %d, want 1", len(config.Categories))
	}
	if len(config.Severities) != 1 {
		t.Errorf("Severities count = %d, want 1", len(config.Severities))
	}
	if len(config.CWEs) != 2 {
		t.Errorf("CWEs count = %d, want 2", len(config.CWEs))
	}
}

func TestSuppressionConfig_IsEmpty(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		var config *SuppressionConfig
		if !config.IsEmpty() {
			t.Error("nil config should be empty")
		}
	})

	t.Run("new config", func(t *testing.T) {
		config := NewSuppressionConfig()
		if !config.IsEmpty() {
			t.Error("new config should be empty")
		}
	})

	t.Run("config with directive", func(t *testing.T) {
		config := NewSuppressionConfig()
		config.Add(SuppressionDirective{Type: DirectiveCWE, Value: "798"})
		if config.IsEmpty() {
			t.Error("config with directive should not be empty")
		}
	})
}

func TestCategoryMapping(t *testing.T) {
	mapping := CategoryMapping()

	expectedCategories := []string{"sast", "secrets", "iac", "sca", "license"}
	for _, cat := range expectedCategories {
		if _, ok := mapping[cat]; !ok {
			t.Errorf("CategoryMapping missing category %q", cat)
		}
	}

	if len(mapping) != 5 {
		t.Errorf("CategoryMapping has %d categories, want 5", len(mapping))
	}

	// Verify deep copy (modifying returned map doesn't affect source)
	mapping["sast"] = []string{"modified"}
	original := CategoryMapping()
	if len(original["sast"]) == 1 && original["sast"][0] == "modified" {
		t.Error("CategoryMapping should return a deep copy")
	}
}

func TestValidateCWE(t *testing.T) {
	tests := []struct {
		value          string
		wantNormalized string
		wantValid      bool
		wantWarning    string
	}{
		{"798", "798", true, ""},
		{"79", "79", true, ""},
		{"1", "1", true, ""},
		{"0079", "79", true, ""},
		{"0", "0", true, "cwe:0 will never match any findings"},
		{"-1", "", false, `invalid cwe value "-1" ignored (must be a non-negative integer)`},
		{"abc", "", false, `invalid cwe value "abc" ignored (must be a non-negative integer)`},
		{"", "", false, "empty cwe directive ignored"},
		{"12.5", "", false, `invalid cwe value "12.5" ignored (must be a non-negative integer)`},
	}

	for _, tt := range tests {
		t.Run("cwe:"+tt.value, func(t *testing.T) {
			normalized, valid, warning := validateCWE(tt.value)
			if valid != tt.wantValid {
				t.Errorf("validateCWE(%q) valid = %v, want %v", tt.value, valid, tt.wantValid)
			}
			if normalized != tt.wantNormalized {
				t.Errorf("validateCWE(%q) normalized = %q, want %q", tt.value, normalized, tt.wantNormalized)
			}
			if warning != tt.wantWarning {
				t.Errorf("validateCWE(%q) warning = %q, want %q", tt.value, warning, tt.wantWarning)
			}
		})
	}
}

func TestHasDirectivePrefix(t *testing.T) {
	tests := []struct {
		line string
		want bool
	}{
		{"rule:CKV_AWS_18", true},
		{"category:secrets", true},
		{"severity:HIGH", true},
		{"cwe:798", true},
		{"Rule:CKV_AWS_18", true},   // case insensitive
		{"SEVERITY:HIGH", true},     // case insensitive
		{"vendor/", false},          // path pattern
		{"*.log", false},            // path pattern
		{"invalid:foo", false},      // unrecognized prefix
		{"# cwe:798", false},        // comment (but hasDirectivePrefix doesn't check for #)
		{"norule:something", false}, // not a prefix match
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			got := hasDirectivePrefix(tt.line)
			if got != tt.want {
				t.Errorf("hasDirectivePrefix(%q) = %v, want %v", tt.line, got, tt.want)
			}
		})
	}
}
