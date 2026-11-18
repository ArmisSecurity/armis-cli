package util

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxControlInput caps the text StripControl reads: it is server text shown
// to a user, and more than 64 KiB of it is never readable on a terminal.
const maxControlInput = 64 << 10

// cutMarker ends the output of a text cut at maxControlInput.
const cutMarker = "…"

// StripControl removes C0 and C1 control characters, such as terminal
// escapes, from text a server sent before it reaches the terminal. Line
// breaks, tabs and the other spacing controls separate words, so a run of
// whitespace that holds a \n, \r, \t, \v, \f or U+0085 (NEL) becomes one
// space between words and is dropped at either end. Other text, spaces and
// non-ASCII letters included, is kept as sent. Only the first
// maxControlInput bytes are read, cut at a rune boundary, and a cut text ends
// in "…". The output is at most that long, or three times that for invalid
// UTF-8, whose bytes each become U+FFFD.
func StripControl(s string) string {
	cut := false
	if len(s) > maxControlInput {
		// Back off to the start of the rune at the cap, at most the
		// length of one rune, so invalid UTF-8 cannot walk it to zero.
		i := maxControlInput
		for j := 1; j < utf8.UTFMax && !utf8.RuneStart(s[i]); j++ {
			i--
		}
		s, cut = s[:i], true
	}
	var b strings.Builder
	spaces := 0     // spaces seen since the last word, not yet written
	breaks := false // the run of whitespace holds a break
	for _, r := range s {
		switch {
		case r == '\n', r == '\r', r == '\t', r == '\v', r == '\f', r == '\u0085':
			breaks = true
		case r == ' ':
			spaces++
		case unicode.IsControl(r):
			// Dropped; it does not end a run of whitespace.
		default:
			if breaks {
				if b.Len() > 0 {
					b.WriteByte(' ')
				}
			} else {
				b.WriteString(strings.Repeat(" ", spaces))
			}
			spaces, breaks = 0, false
			b.WriteRune(r)
		}
	}
	if !breaks {
		b.WriteString(strings.Repeat(" ", spaces))
	}
	if cut {
		b.WriteString(cutMarker)
	}
	return b.String()
}
