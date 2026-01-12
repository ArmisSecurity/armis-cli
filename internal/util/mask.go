// Package util provides utility functions for the CLI.
package util

import (
	"regexp"
	"strings"
)

// secretPatterns contains regex patterns for detecting secrets in code.
// Each pattern captures a prefix (keyword) and the secret value.
// IMPORTANT: Patterns are ordered from most specific to least specific to prevent
// early matches by generic patterns (e.g., "secret" in password patterns matching
// before the more specific AWS credentials pattern).
var secretPatterns = []*regexp.Regexp{
	// AWS credentials (most specific - matches aws_secret_access_key before generic "secret")
	regexp.MustCompile(`(?i)(aws[-_]?access[-_]?key[-_]?id|aws[-_]?secret[-_]?access[-_]?key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{16,})['"]?`),
	// Private keys (detect key content)
	regexp.MustCompile(`(?i)(private[-_]?key|privatekey)\s*[:=]\s*['"]?([^\s'"]{10,})['"]?`),
	// Connection strings
	regexp.MustCompile(`(?i)(connection[-_]?string|conn[-_]?str)\s*[:=]\s*['"]?([^\s'"]{10,})['"]?`),
	// API keys and tokens (various formats)
	regexp.MustCompile(`(?i)(api[-_]?key|apikey|api_token|access[-_]?token|auth[-_]?token|bearer|token)\s*[:=]\s*['"]?([A-Za-z0-9_./+=-]{8,})['"]?`),
	// JWT tokens - header starts with eyJ (base64 of '{"'), payload and signature are any base64url
	regexp.MustCompile(`(eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)`),
	// Password patterns
	regexp.MustCompile(`(?i)(password|passwd|pwd|secret)\s*[:=]\s*['"]?([^\s'"]{4,})['"]?`),
	// Hex strings that look like secrets (32+ chars)
	regexp.MustCompile(`(?i)(secret|key|hash)\s*[:=]\s*['"]?([A-Fa-f0-9]{32,})['"]?`),
	// Generic credentials (least specific) - uses word boundaries and 8-char minimum
	// to reduce false positives on common variable names like 'authService' or 'credType'
	regexp.MustCompile(`(?i)\b(credential|cred|auth)\b\s*[:=]\s*['"]?([^\s'"]{8,})['"]?`),
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
				masked := maskValue(value)
				return strings.Replace(match, value, masked, 1)
			}

			// For patterns without prefix (like JWT), mask the whole match
			return maskValue(match)
		})
	}

	return result
}

// maskValue masks a secret value, preserving some structure hints.
// Shows first 2 chars and last 2 chars if long enough, otherwise all asterisks.
func maskValue(value string) string {
	if len(value) <= 4 {
		return strings.Repeat("*", len(value))
	}

	// For longer values, show partial hints
	if len(value) <= 8 {
		return value[:1] + strings.Repeat("*", len(value)-2) + value[len(value)-1:]
	}

	// For very long values, show first 2 and last 2
	return value[:2] + strings.Repeat("*", len(value)-4) + value[len(value)-2:]
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
