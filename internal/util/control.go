package util

import (
	"strings"
	"unicode"
)

// StripControl removes C0 and C1 control characters, such as terminal
// escapes, from text a server sent before it reaches the terminal.
func StripControl(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}
