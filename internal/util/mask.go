// Package util provides utility functions for the CLI.
package util

import (
	"fmt"
	"regexp"
	"strings"
)

// secretPatterns contains regex patterns for detecting secrets in code.
// Each pattern captures a prefix (keyword) and the secret value.
// IMPORTANT: Patterns are ordered from most specific to least specific to prevent
// early matches by generic patterns (e.g., "secret" in password patterns matching
// before the more specific AWS credentials pattern).
// Assignment operators supported: =, :, :=, =>
// The regex (?::=|[:=]>?) matches := first, then falls back to :, =, =>, or :>
var secretPatterns = []*regexp.Regexp{
	// Well-known secret prefixes (standalone, no assignment needed)
	// These catch secrets by their identifying prefix patterns
	regexp.MustCompile(`['"]?(sk[-_](?:live|test|proj)[-_][A-Za-z0-9]{20,})['"]?`),                                         // Stripe/OpenAI secret keys (specific)
	regexp.MustCompile(`['"]?(sk-[A-Za-z0-9]{20,})['"]?`),                                                                  // Generic sk- tokens (OpenAI, etc.)
	regexp.MustCompile(`['"]?(pk[-_](?:live|test)[-_][A-Za-z0-9]{20,})['"]?`),                                              // Stripe publishable keys
	regexp.MustCompile(`['"]?(AIzaSy[A-Za-z0-9_-]{33})['"]?`),                                                              // Google/Firebase API keys
	regexp.MustCompile(`['"]?(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})['"]?`),                                             // SendGrid API keys
	regexp.MustCompile(`['"]?(xox[baprs]-[A-Za-z0-9-]{10,})['"]?`),                                                         // Slack tokens
	regexp.MustCompile(`['"]?(ghp_[A-Za-z0-9]{36,})['"]?`),                                                                 // GitHub PATs (new format)
	regexp.MustCompile(`['"]?(gho_[A-Za-z0-9]{36,})['"]?`),                                                                 // GitHub OAuth tokens
	regexp.MustCompile(`['"]?(glpat-[A-Za-z0-9_-]{20,})['"]?`),                                                             // GitLab PATs
	regexp.MustCompile(`['"]?(AKIA[A-Z0-9]{16})['"]?`),                                                                     // AWS access key IDs
	regexp.MustCompile(`['"]?(AC[a-zA-Z0-9]{32})['"]?`),                                                                    // Twilio Account SIDs
	regexp.MustCompile(`['"]?(token_[A-Za-z0-9]{20,})['"]?`),                                                               // token_ prefix values (e.g., token_1234567890...)
	regexp.MustCompile(`['"]?(key-[a-f0-9]{32})['"]?`),                                                                     // Mailgun API keys
	regexp.MustCompile(`['"]?(DefaultEndpointsProtocol=https;[^'"]{20,})['"]?`),                                            // Azure connection strings
	regexp.MustCompile(`['"]?(mongodb(?:\+srv)?://[^'"]{10,})['"]?`),                                                       // MongoDB connection strings
	regexp.MustCompile(`['"]?(postgresql://[^'"]{10,})['"]?`),                                                              // PostgreSQL connection strings
	regexp.MustCompile(`['"]?(mysql://[^'"]{10,})['"]?`),                                                                   // MySQL connection strings
	regexp.MustCompile(`['"]?(https://hooks\.slack\.com/services/[A-Za-z0-9/]+)['"]?`),                                     // Slack webhooks
	regexp.MustCompile(`['"]?(https://[A-Za-z0-9]+@[A-Za-z0-9]+\.ingest\.sentry\.io/[0-9]+)['"]?`),                         // Sentry DSN URLs
	regexp.MustCompile(`['"]?(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[^'"]+-----END[^'"]+-----)['"]?`), // Private keys

	// AWS credentials (most specific - matches aws_secret_access_key before generic "secret")
	regexp.MustCompile(`(?i)(aws[-_]?access[-_]?key[-_]?id|aws[-_]?secret[-_]?access[-_]?key)\s*(?::=|[:=]>?)\s*['"]?([A-Za-z0-9/+=]{16,})['"]?`),
	// Private keys (detect key content; require 16+ chars to reduce false positives)
	regexp.MustCompile(`(?i)(private[-_]?key|privatekey|ssh[-_]?key|ssh[-_]?private[-_]?key)\s*(?::=|[:=]>?)\s*['"]?([^\s'"]{16,})['"]?`),
	// OAuth client secrets
	regexp.MustCompile(`(?i)(client[-_]?secret|client[-_]?id)\s*(?::=|[:=]>?)\s*['"]?([A-Za-z0-9_./+=-]{10,})['"]?`),
	// Database connection strings and passwords
	regexp.MustCompile(`(?i)(database[-_]?url|db[-_]?password|db[-_]?pass|database[-_]?password)\s*(?::=|[:=]>?)\s*['"]?([^\s'"]{8,})['"]?`),
	// Connection strings (require 10+ chars to reduce false positives)
	regexp.MustCompile(`(?i)(connection[-_]?string|conn[-_]?str)\s*(?::=|[:=]>?)\s*['"]?([^\s'"]{10,})['"]?`),

	// Service-specific tokens - expanded list
	regexp.MustCompile(`(?i)(slack[-_]?token|discord[-_]?token|stripe[-_]?(?:key|secret|api[-_]?key)|twilio[-_]?(?:auth|token|sid)|npm[-_]?token|pypi[-_]?token|github[-_]?token|gitlab[-_]?token|openai[-_]?(?:key|api[-_]?key)|azure[-_]?(?:key|connection[-_]?string)|sendgrid[-_]?(?:key|api[-_]?key)|firebase[-_]?(?:key|api[-_]?key)|mailchimp[-_]?(?:key|api[-_]?key)|mailgun[-_]?(?:key|api[-_]?key)|algolia[-_]?(?:key|api[-_]?key|app[-_]?id)|mapbox[-_]?(?:token|key)|datadog[-_]?(?:key|api[-_]?key)|pagerduty[-_]?(?:key|api[-_]?key)|newrelic[-_]?(?:key|license[-_]?key)|paypal[-_]?(?:secret|client[-_]?id)|square[-_]?token)\s*(?::=|[:=]>?)\s*['"]?([A-Za-z0-9_./+=-]{10,})['"]?`),

	// API keys and tokens (require 10+ chars to avoid short non-secrets)
	regexp.MustCompile(`(?i)(api[-_]?key|apikey|api_token|access[-_]?token|auth[-_]?token|bearer|token)\s*(?::=|[:=]>?)\s*['"]?([A-Za-z0-9_./+=-]{10,})['"]?`),
	// Signing and encryption keys
	regexp.MustCompile(`(?i)(signing[-_]?key|encryption[-_]?key|secret[-_]?key)\s*(?::=|[:=]>?)\s*['"]?([^\s'"]{16,})['"]?`),
	// JWT tokens - header starts with eyJ (base64 of '{"'), payload and signature are any base64url
	regexp.MustCompile(`(eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)`),
	// Bearer tokens in Authorization headers - "Bearer <token>" without assignment operator
	regexp.MustCompile(`['"]?Bearer\s+([A-Za-z0-9_./+=-]{20,})['"]?`),
	// Password patterns (require 8+ chars to reduce false positives)
	regexp.MustCompile(`(?i)(password|passwd|pwd|secret)\s*(?::=|[:=]>?)\s*['"]?([^\s'"]{8,})['"]?`),
	// Hex strings that look like secrets (32+ chars)
	regexp.MustCompile(`(?i)(secret|key|hash)\s*(?::=|[:=]>?)\s*['"]?([A-Fa-f0-9]{32,})['"]?`),
	// Generic credentials (least specific) - uses word boundaries and 10-char minimum
	// to reduce false positives on common variable names like 'authService' or 'credType'
	regexp.MustCompile(`(?i)\b(credential|cred|auth)\b\s*(?::=|[:=]>?)\s*['"]?([^\s'"]{10,})['"]?`),

	// Generic catch-all for any identifier ending in _key, _secret, _token, _auth, _password
	// with object prefix (self., this., obj.) - handles self.openai_key = "..."
	// Requires quoted string value to avoid matching os.Getenv() calls
	regexp.MustCompile(`(?i)(?:self\.|this\.)?([a-z_][a-z0-9_]*[-_](?:key|secret|token|auth|password))\s*(?::=|[:=]>?)\s*['"]([^'"]{10,})['"]`),

	// Dict/JSON literals with quoted keys - handles {"api_key": "value"}, "password": "value", etc.
	// Matches: bare keywords (password, secret, token) OR compound keys (api_key, auth_token) OR private_key_id
	// Two capture groups: (1) key name, (2) value - so masking preserves the key
	regexp.MustCompile(`(?i)['"](password|secret|token|auth|credential|private[-_]?key[-_]?id|[a-z_][a-z0-9_]*[-_](?:key|secret|token|auth|password|credential))['"]\s*:\s*['"]([^'"]{10,})['"]`),
}

// commonLiterals contains values that should not be masked even if they match a pattern.
// These are common programming literals and function names that aren't secrets.
var commonLiterals = map[string]bool{
	"true": true, "false": true, "null": true, "nil": true,
	"undefined": true, "none": true, "empty": true,
}

// MaskSecretInLine replaces secret values in a line with asterisks while
// preserving the code structure. Returns the masked line.
func MaskSecretInLine(line string) string {
	if line == "" {
		return line
	}

	result := line

	for _, pattern := range secretPatterns {
		result = pattern.ReplaceAllStringFunc(result, func(match string) string {
			// Find the submatch to determine what to mask
			submatches := pattern.FindStringSubmatch(match)
			if len(submatches) < 2 {
				return match
			}

			// For patterns with prefix + value (3+ capture groups), mask just the value (submatches[2])
			if len(submatches) >= 3 {
				value := submatches[2]
				// Skip common literals that aren't secrets
				if commonLiterals[strings.ToLower(value)] {
					return match
				}
				masked := maskValue(value)
				return strings.Replace(match, value, masked, 1)
			}

			// For patterns with a single capture group (well-known prefixes, JWT, Bearer, etc.),
			// mask the captured value and replace it in the match to preserve surrounding structure
			// (quotes, "Bearer " prefix, etc.)
			value := submatches[1]
			if commonLiterals[strings.ToLower(value)] {
				return match
			}
			masked := maskValue(value)
			return strings.Replace(match, value, masked, 1)
		})
	}

	return result
}

// maskValue masks a secret value completely for security.
// Only reveals a length range of the original value, not any actual characters.
// This prevents leaking prefixes that identify secret types (e.g., "eyJ" for JWT,
// "ghp_" for GitHub tokens, "AKIA" for AWS keys, "sk_live_" for Stripe).
// Length ranges are used instead of exact lengths to prevent token type identification.
func maskValue(value string) string {
	length := len(value)
	if length == 0 {
		return ""
	}
	if length < 10 {
		// For short values (up to 9 chars), show asterisks matching length
		return strings.Repeat("*", length)
	}
	// For longer values, show length range to prevent token type identification
	// (e.g., GitHub PATs ~40 chars, AWS keys 40 chars could be fingerprinted)
	var rangeStr string
	switch {
	case length <= 20:
		rangeStr = "10-20"
	case length <= 40:
		rangeStr = "20-40"
	case length <= 80:
		rangeStr = "40-80"
	default:
		rangeStr = "80+"
	}
	return fmt.Sprintf("********[%s]", rangeStr)
}

// MaskSecretInLines masks secrets in multiple lines.
func MaskSecretInLines(lines []string) []string {
	if lines == nil {
		return nil
	}

	masked := make([]string, len(lines))
	for i, line := range lines {
		masked[i] = MaskSecretInLine(line)
	}
	return masked
}

// MaskSecretInMultiLineString masks secrets in a string that may contain newlines.
// Each line is processed independently to handle multi-line content like patches.
func MaskSecretInMultiLineString(s string) string {
	if s == "" {
		return s
	}
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = MaskSecretInLine(line)
	}
	return strings.Join(lines, "\n")
}

// MaskSecretsInStringMap masks secrets in all values of a string map.
// Keys are preserved; values are processed through MaskSecretInMultiLineString.
// Returns a new map; the original is not modified.
func MaskSecretsInStringMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	result := make(map[string]string, len(m))
	for k, v := range m {
		result[k] = MaskSecretInMultiLineString(v)
	}
	return result
}
