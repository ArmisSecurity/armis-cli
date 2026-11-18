package util

import (
	"strings"
	"unicode"
)

// StripControl removes C0 and C1 control characters, such as terminal
// escapes, from text a server sent before it reaches the terminal. Line
// breaks, tabs and the other spacing controls separate words, so a run of
// whitespace that holds a \n, \r, \t, \v, \f or U+0085 (NEL) becomes one
// space between words and is dropped at either end. Other text, spaces and
// non-ASCII letters included, is kept as sent.
func StripControl(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	var run strings.Builder // spaces seen since the last word, not yet written
	breaks := false         // the run holds a break: \n, \r, \t, \v, \f or NEL
	for _, r := range s {
		switch {
		case strings.ContainsRune("\n\r\t\v\f\u0085", r):
			breaks = true
		case r == ' ':
			run.WriteRune(r)
		case unicode.IsControl(r):
			// Dropped; it does not end a run of whitespace.
		default:
			if breaks {
				if b.Len() > 0 {
					b.WriteByte(' ')
				}
			} else {
				b.WriteString(run.String())
			}
			run.Reset()
			breaks = false
			b.WriteRune(r)
		}
	}
	if !breaks {
		b.WriteString(run.String())
	}
	return b.String()
}
