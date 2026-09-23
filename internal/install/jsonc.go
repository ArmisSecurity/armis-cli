package install

import "bytes"

// utf8BOM is the byte-order mark Windows Notepad (and some other editors)
// prepend when saving a file as UTF-8. encoding/json rejects it.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// stripJSONC converts JSON-with-comments (the format VS Code uses for
// mcp.json and settings.json) into plain JSON: it removes a leading UTF-8
// BOM, // line comments, /* block */ comments, and trailing commas before a
// closing } or ]. String contents are left untouched, including escaped
// quotes and comment-like sequences such as "http://...".
//
// Without this, a hand-edited mcp.json with a single comment fails to parse:
// the doctor misreports it as invalid, and a re-registration would start from
// an empty map and drop every other server in the file.
func stripJSONC(in []byte) []byte {
	in = bytes.TrimPrefix(in, utf8BOM)
	out := make([]byte, 0, len(in))

	inString := false
	for i := 0; i < len(in); i++ {
		c := in[i]
		if inString {
			out = append(out, c)
			switch c {
			case '\\':
				if i+1 < len(in) {
					i++
					out = append(out, in[i])
				}
			case '"':
				inString = false
			}
			continue
		}

		switch {
		case c == '"':
			inString = true
			out = append(out, c)
		case c == '/' && i+1 < len(in) && in[i+1] == '/':
			for i < len(in) && in[i] != '\n' {
				i++
			}
			if i < len(in) {
				out = append(out, '\n')
			}
		case c == '/' && i+1 < len(in) && in[i+1] == '*':
			i += 2
			for i+1 < len(in) && (in[i] != '*' || in[i+1] != '/') {
				i++
			}
			i++ // skip the closing '/'
		case c == ',':
			// Drop a trailing comma: look past whitespace and comments for the
			// next significant byte.
			if next := nextSignificant(in, i+1); next == '}' || next == ']' {
				continue
			}
			out = append(out, c)
		default:
			out = append(out, c)
		}
	}
	return out
}

// nextSignificant returns the first byte at or after start that is not
// whitespace or part of a comment, or 0 at end of input.
func nextSignificant(in []byte, start int) byte {
	for i := start; i < len(in); i++ {
		switch c := in[i]; {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
		case c == '/' && i+1 < len(in) && in[i+1] == '/':
			for i < len(in) && in[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(in) && in[i+1] == '*':
			i += 2
			for i+1 < len(in) && (in[i] != '*' || in[i+1] != '/') {
				i++
			}
			i++
		default:
			return c
		}
	}
	return 0
}
