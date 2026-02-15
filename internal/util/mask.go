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
	// Service-specific tokens (Slack, Discord, Stripe, etc.)
	regexp.MustCompile(`(?i)(slack[-_]?token|discord[-_]?token|stripe[-_]?key|stripe[-_]?secret|twilio[-_]?auth|npm[-_]?token|pypi[-_]?token|github[-_]?token|gitlab[-_]?token)\s*(?::=|[:=]>?)\s*['"]?([A-Za-z0-9_./+=-]{10,})['"]?`),
	// API keys and tokens (require 10+ chars to avoid short non-secrets)
	regexp.MustCompile(`(?i)(api[-_]?key|apikey|api_token|access[-_]?token|auth[-_]?token|bearer|token)\s*(?::=|[:=]>?)\s*['"]?([A-Za-z0-9_./+=-]{10,})['"]?`),
	// Signing and encryption keys
	regexp.MustCompile(`(?i)(signing[-_]?key|encryption[-_]?key|secret[-_]?key)\s*(?::=|[:=]>?)\s*['"]?([^\s'"]{16,})['"]?`),
	// JWT tokens - header starts with eyJ (base64 of '{"'), payload and signature are any base64url
	regexp.MustCompile(`(eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)`),
	// Password patterns (require 8+ chars to reduce false positives)
	regexp.MustCompile(`(?i)(password|passwd|pwd|secret)\s*(?::=|[:=]>?)\s*['"]?([^\s'"]{8,})['"]?`),
	// Hex strings that look like secrets (32+ chars)
	regexp.MustCompile(`(?i)(secret|key|hash)\s*(?::=|[:=]>?)\s*['"]?([A-Fa-f0-9]{32,})['"]?`),
	// Generic credentials (least specific) - uses word boundaries and 10-char minimum
	// to reduce false positives on common variable names like 'authService' or 'credType'
	regexp.MustCompile(`(?i)\b(credential|cred|auth)\b\s*(?::=|[:=]>?)\s*['"]?([^\s'"]{10,})['"]?`),
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

			// For patterns with prefix + value, mask just the value
			if len(submatches) >= 3 {
				value := submatches[2]
				// Skip common literals that aren't secrets
				if commonLiterals[strings.ToLower(value)] {
					return match
				}
				masked := maskValue(value)
				return strings.Replace(match, value, masked, 1)
			}

			// For patterns without prefix (like JWT), mask the whole match
			return maskValue(match)
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
