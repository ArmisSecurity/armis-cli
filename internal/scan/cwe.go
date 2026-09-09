package scan

import (
	"regexp"
	"strings"
)

// cweNumberPattern matches the identifier at the head of a CWE string. It is a
// prefix match, not an anchor on the whole string: the backend spells the same CWE
// as "CWE-78", "cwe-78", "CWE-78: OS Command Injection" and
// "CWE-78 - OS Command Injection", and every one of those must reduce to 78.
var cweNumberPattern = regexp.MustCompile(`(?i)^CWE-(\d+)`)

// cweBareNumberPattern matches a CWE given as a bare integer, e.g. "78".
var cweBareNumberPattern = regexp.MustCompile(`^\d+$`)

// CWENumber extracts the bare CWE number from any spelling the backend emits, and
// reports whether one was found.
//
// This is the single CWE parser in the codebase. Suppression matching
// (.armisignore `cwe:` directives) and dedupe identity both use it, so a spelling
// one of them tolerates cannot be a spelling the other silently fails on -- which
// previously meant "CWE-78 - OS Command Injection" was suppressible but stopped two
// real duplicates from collapsing.
func CWENumber(cwe string) (string, bool) {
	trimmed := strings.TrimSpace(cwe)
	if matches := cweNumberPattern.FindStringSubmatch(trimmed); len(matches) == 2 {
		return matches[1], true
	}
	if cweBareNumberPattern.MatchString(trimmed) {
		return trimmed, true
	}
	return "", false
}
