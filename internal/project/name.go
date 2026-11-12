// Package project implements the CLI side of AppSec projects: validating a
// --project name, deciding whether a scan is published to its project, and
// resolving (or creating) the project a published scan is recorded on.
package project

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxNameLength is the longest project name the AppSec API accepts.
const MaxNameLength = 64

// fallbackExample is the valid name suggested when nothing usable can be
// derived from the rejected input.
const fallbackExample = "my-project"

// maxListedChars caps how many distinct disallowed characters an error lists.
const maxListedChars = 5

// maxDisplayedNameRunes caps how much of a rejected name is echoed back, so a
// pasted blob does not flood the terminal.
const maxDisplayedNameRunes = 80

// ErrInvalidName is matched (via errors.Is) by every *NameError.
var ErrInvalidName = errors.New("invalid project name")

// Rule identifies one project-name rule, so callers and tests can tell which
// rule was broken without matching on message text.
type Rule string

const (
	// RuleEmpty: the name is empty or only whitespace.
	RuleEmpty Rule = "empty"
	// RuleTooLong: the name is longer than MaxNameLength characters.
	RuleTooLong Rule = "too_long"
	// RuleCharset: the name holds a character outside A-Z a-z 0-9 . _ - /.
	RuleCharset Rule = "charset"
	// RuleBoundary: the name starts or ends with '.', '_', '-' or '/'.
	RuleBoundary Rule = "boundary"
	// RuleReserved: the name is a reserved word.
	RuleReserved Rule = "reserved"
)

// reservedNames are rejected case-insensitively. They are the values an unset
// CI or template variable renders as (`${PROJECT}` from a YAML null, Python's
// None, Go's <nil> once stripped, JavaScript's undefined), so a pipeline with a
// missing variable fails loudly instead of creating a project called "null".
var reservedNames = []string{"null", "nil", "none", "undefined"}

// Violation is one broken rule with a human-readable explanation.
type Violation struct {
	Rule    Rule
	Message string
}

// NameError reports every rule a --project name breaks, plus a valid example
// the user can copy. The name is never trimmed, truncated or renamed: the CLI
// rejects it and says how to fix it.
type NameError struct {
	Name       string
	Violations []Violation
	Example    string
}

// Error renders the rejected name, each broken rule, and a valid example.
func (e *NameError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "invalid --project name %s: ", displayName(e.Name))
	if len(e.Violations) == 1 {
		b.WriteString(e.Violations[0].Message)
	} else {
		fmt.Fprintf(&b, "%d problems:", len(e.Violations))
		for _, v := range e.Violations {
			b.WriteString("\n  - ")
			b.WriteString(v.Message)
		}
	}
	fmt.Fprintf(&b, "\n  Example of a valid name: --project %s", e.Example)
	return b.String()
}

// Is makes errors.Is(err, ErrInvalidName) true for any *NameError.
func (e *NameError) Is(target error) bool {
	return target == ErrInvalidName
}

// Broken reports whether the error includes a violation of rule.
func (e *NameError) Broken(rule Rule) bool {
	for _, v := range e.Violations {
		if v.Rule == rule {
			return true
		}
	}
	return false
}

// ValidateName checks a --project name against the AppSec naming rules and
// returns a *NameError listing every rule it breaks, or nil when it is valid:
//
//   - 1 to 64 characters;
//   - only ASCII letters, digits, '.', '_', '-' and '/' (the API's own rule);
//   - starts and ends with a letter or digit, so a flag swallowed as the value
//     (`--project --sync`), a path (`.`, `..`, `/src`) or a stray separator is
//     caught rather than becoming a project;
//   - not a reserved word (null, nil, none, undefined).
//
// The first two rules mirror the API; the last two are the CLI's own, because
// the API accepts `.`, `--sync` and `null` as names.
func ValidateName(name string) error {
	if strings.TrimSpace(name) == "" {
		msg := "it is empty; a project name needs 1 to 64 characters"
		if name != "" {
			msg = "it is only whitespace; a project name needs 1 to 64 characters"
		}
		return &NameError{
			Name:       name,
			Violations: []Violation{{Rule: RuleEmpty, Message: msg}},
			Example:    fallbackExample,
		}
	}

	var violations []Violation

	if n := utf8.RuneCountInString(name); n > MaxNameLength {
		violations = append(violations, Violation{
			Rule:    RuleTooLong,
			Message: fmt.Sprintf("it is %d characters long; the maximum is %d", n, MaxNameLength),
		})
	}

	if bad := disallowedChars(name); len(bad) > 0 {
		violations = append(violations, Violation{
			Rule: RuleCharset,
			Message: fmt.Sprintf("it contains %s: %s; use only letters (A-Z, a-z), digits (0-9), '.', '_', '-' and '/'",
				pluralize(len(bad), "a character that is not allowed", "characters that are not allowed"), listChars(bad)),
		})
	}

	// Only judge the boundaries on allowed characters: a leading space or '@'
	// is already reported by the charset rule above.
	first, _ := utf8.DecodeRuneInString(name)
	last, _ := utf8.DecodeLastRuneInString(name)
	switch {
	case isSeparator(first):
		msg := fmt.Sprintf("it must start with a letter or digit, not %s", strconv.QuoteRune(first))
		if looksLikeFlag(name) {
			msg += " (it looks like a command-line flag: did --project miss its value?)"
		}
		violations = append(violations, Violation{Rule: RuleBoundary, Message: msg})
	case isSeparator(last):
		violations = append(violations, Violation{
			Rule:    RuleBoundary,
			Message: fmt.Sprintf("it must end with a letter or digit, not %s", strconv.QuoteRune(last)),
		})
	}

	if isReserved(name) {
		violations = append(violations, Violation{
			Rule:    RuleReserved,
			Message: fmt.Sprintf("%q is a reserved word (it is what an unset CI or template variable renders as)", name),
		})
	}

	if len(violations) == 0 {
		return nil
	}
	return &NameError{Name: name, Violations: violations, Example: suggestName(name)}
}

// isAllowed reports whether r may appear in a project name.
func isAllowed(r rune) bool {
	return isAlnum(r) || isSeparator(r)
}

// isAlnum reports whether r is an ASCII letter or digit.
func isAlnum(r rune) bool {
	return ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z') || ('0' <= r && r <= '9')
}

// isSeparator reports whether r is one of the allowed non-alphanumeric characters.
func isSeparator(r rune) bool {
	return r == '.' || r == '_' || r == '-' || r == '/'
}

// isReserved reports whether name is a reserved word, ignoring case.
func isReserved(name string) bool {
	for _, w := range reservedNames {
		if strings.EqualFold(name, w) {
			return true
		}
	}
	return false
}

// looksLikeFlag reports whether name looks like a CLI flag that pflag consumed
// as --project's value (`--project --sync`, `--project -o`).
func looksLikeFlag(name string) bool {
	return strings.HasPrefix(name, "--") || (len(name) == 2 && name[0] == '-' && isAlnum(rune(name[1])))
}

// disallowedChars returns the distinct disallowed runes of name, in order of
// first appearance. An invalid UTF-8 byte is reported as U+FFFD.
func disallowedChars(name string) []rune {
	var bad []rune
	seen := map[rune]bool{}
	for _, r := range name {
		if !isAllowed(r) && !seen[r] {
			seen[r] = true
			bad = append(bad, r)
		}
	}
	return bad
}

// listChars renders runes for an error message: quoted with Go escaping so an
// invisible character shows as '\u200b', and capped at maxListedChars.
func listChars(runes []rune) string {
	parts := make([]string, 0, maxListedChars+1)
	for i, r := range runes {
		if i == maxListedChars {
			parts = append(parts, fmt.Sprintf("and %d more", len(runes)-maxListedChars))
			break
		}
		q := strconv.QuoteRune(r)
		if r == ' ' {
			q += " (space)"
		}
		parts = append(parts, q)
	}
	return strings.Join(parts, ", ")
}

// suggestName derives a valid example from a rejected name: disallowed runs
// become '-', the edges are trimmed to a letter or digit, and the result is cut
// to MaxNameLength. When nothing usable remains (or the input looked like a
// flag, which carries no real name), it falls back to fallbackExample. The
// result always passes ValidateName.
func suggestName(name string) string {
	if looksLikeFlag(name) {
		return fallbackExample
	}

	// Disallowed runs become a single '-', merged with any adjacent '-'.
	var b strings.Builder
	lastDash := false
	for _, r := range name {
		if !isAllowed(r) {
			r = '-'
		}
		if r == '-' && lastDash {
			continue
		}
		b.WriteRune(r)
		lastDash = r == '-'
	}

	s := trimToAlnum(b.String())
	if len(s) > MaxNameLength { // ASCII only by now, so bytes == characters
		s = trimToAlnum(s[:MaxNameLength])
	}
	if s == "" || isReserved(s) {
		return fallbackExample
	}
	return s
}

// trimToAlnum trims leading and trailing separators. The input is ASCII.
func trimToAlnum(s string) string {
	return strings.TrimFunc(s, isSeparator)
}

// displayName quotes name for an error message, escaping invisible characters
// and shortening very long input.
func displayName(name string) string {
	if utf8.RuneCountInString(name) <= maxDisplayedNameRunes {
		return strconv.Quote(name)
	}
	runes := []rune(name)
	return strconv.Quote(string(runes[:maxDisplayedNameRunes])) + "..."
}

// pluralize picks the singular or plural phrase for n.
func pluralize(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}
