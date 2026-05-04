package repo

import (
	"fmt"
	"strconv"
	"strings"
)

// maxIgnoreFileLines is the maximum number of lines parsed from a .armisignore file.
// Lines beyond this limit are truncated with a warning (fail-open per ADR-0008 Section 12).
const maxIgnoreFileLines = 1000

// DirectiveType represents the type of a suppression directive.
type DirectiveType string

const (
	DirectiveRule     DirectiveType = "rule"
	DirectiveCategory DirectiveType = "category"
	DirectiveSeverity DirectiveType = "severity"
	DirectiveCWE      DirectiveType = "cwe"
)

// SuppressionDirective represents a single parsed finding-level suppression directive.
type SuppressionDirective struct {
	Type   DirectiveType
	Value  string // normalized: severity uppercase, category lowercase, cwe bare int string, rule as-is
	Reason string // optional text after " -- " delimiter
}

// SuppressionConfig holds all parsed finding-level suppression directives from .armisignore.
type SuppressionConfig struct {
	Rules      []SuppressionDirective
	Categories []SuppressionDirective
	Severities []SuppressionDirective
	CWEs       []SuppressionDirective
}

var validSeverities = map[string]bool{
	"CRITICAL": true,
	"HIGH":     true,
	"MEDIUM":   true,
	"LOW":      true,
	"INFO":     true,
}

var validCategories = map[string][]string{
	"sast":    {"CODE_VULNERABILITY", "CLIENT_SIDE_SECURITY_MISUSE", "GENERIC_CODE_QUALITY_ISSUE", "DEBUG_CODE_LEFTOVER"},
	"secrets": {"HARDCODED_SECRET_EXPOSURE", "CREDENTIAL_LEAKAGE"},
	"iac":     {"INFRA_AS_CODE_MISCONFIGURATION", "CI_CD_SECURITY_MISCONFIGURATION", "POLICY_VIOLATION"},
	"sca":     {"CODE_PACKAGE_VULNERABILITY", "CODE_PACKAGE_VULNERABILITY_WITH_NO_FIX", "BASE_IMAGE_VULNERABILITY"},
	"license": {"LICENSE_COMPLIANCE_RISK"},
}

// directivePrefixes defines recognized directive prefixes for quick lookup.
var directivePrefixes = []string{"rule:", "category:", "severity:", "cwe:"}

// NewSuppressionConfig creates an empty SuppressionConfig.
func NewSuppressionConfig() *SuppressionConfig {
	return &SuppressionConfig{}
}

// IsEmpty returns true if no suppression directives have been parsed.
func (c *SuppressionConfig) IsEmpty() bool {
	if c == nil {
		return true
	}
	return len(c.Rules) == 0 && len(c.Categories) == 0 &&
		len(c.Severities) == 0 && len(c.CWEs) == 0
}

// Add appends a directive to the appropriate slice based on its type.
func (c *SuppressionConfig) Add(d SuppressionDirective) {
	switch d.Type {
	case DirectiveRule:
		c.Rules = append(c.Rules, d)
	case DirectiveCategory:
		c.Categories = append(c.Categories, d)
	case DirectiveSeverity:
		c.Severities = append(c.Severities, d)
	case DirectiveCWE:
		c.CWEs = append(c.CWEs, d)
	}
}

// CategoryMapping returns a copy of the customer-facing category to internal classification mapping.
func CategoryMapping() map[string][]string {
	result := make(map[string][]string, len(validCategories))
	for k, v := range validCategories {
		copied := make([]string, len(v))
		copy(copied, v)
		result[k] = copied
	}
	return result
}

// parseDirectiveLine determines whether a line is a finding-level suppression directive.
// Returns the parsed directive and true if it's a directive, or nil and false if it's a
// path pattern (or blank/comment). A non-empty warning is returned for malformed directives.
func parseDirectiveLine(line string) (*SuppressionDirective, bool, string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil, false, ""
	}

	if !hasDirectivePrefix(line) {
		return nil, false, ""
	}

	var reason string
	if idx := strings.Index(line, " -- "); idx >= 0 {
		reason = strings.TrimSpace(line[idx+4:])
		line = strings.TrimSpace(line[:idx])
	}

	colonIdx := strings.Index(line, ":")
	if colonIdx < 0 {
		return nil, false, ""
	}

	prefix := strings.ToLower(line[:colonIdx])
	value := strings.TrimSpace(line[colonIdx+1:])

	switch prefix {
	case "rule":
		if value == "" {
			return nil, false, fmt.Sprintf("empty rule directive ignored: %q", line)
		}
		return &SuppressionDirective{Type: DirectiveRule, Value: value, Reason: reason}, true, ""

	case "category":
		normalized := strings.ToLower(value)
		if _, ok := validCategories[normalized]; !ok {
			return nil, false, fmt.Sprintf("unknown category %q ignored (valid: sast, secrets, iac, sca, license)", value)
		}
		return &SuppressionDirective{Type: DirectiveCategory, Value: normalized, Reason: reason}, true, ""

	case "severity":
		normalized := strings.ToUpper(value)
		if !validSeverities[normalized] {
			return nil, false, fmt.Sprintf("unknown severity %q ignored (valid: CRITICAL, HIGH, MEDIUM, LOW, INFO)", value)
		}
		return &SuppressionDirective{Type: DirectiveSeverity, Value: normalized, Reason: reason}, true, ""

	case "cwe":
		valid, warning := validateCWE(value)
		if !valid {
			return nil, false, warning
		}
		return &SuppressionDirective{Type: DirectiveCWE, Value: value, Reason: reason}, true, warning

	default:
		return nil, false, ""
	}
}

// hasDirectivePrefix checks whether a line starts with any recognized directive prefix.
// This is used before splitting on " -- " to avoid treating path patterns as directives.
func hasDirectivePrefix(line string) bool {
	lower := strings.ToLower(line)
	for _, prefix := range directivePrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// validateCWE checks whether a CWE value string is a valid non-negative integer.
// Returns (valid, warning). When valid is false the directive should be rejected.
// When valid is true but warning is non-empty, the directive is accepted with a warning.
func validateCWE(value string) (bool, string) {
	if value == "" {
		return false, "empty cwe directive ignored"
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return false, fmt.Sprintf("invalid cwe value %q ignored (must be a positive integer)", value)
	}
	if n < 0 {
		return false, fmt.Sprintf("invalid cwe value %q ignored (must be a positive integer)", value)
	}
	if n == 0 {
		return true, "cwe:0 will never match any findings"
	}
	return true, ""
}
