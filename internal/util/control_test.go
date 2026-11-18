package util_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ArmisSecurity/armis-cli/internal/util"
)

func TestStripControl(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"plain text", "plain text", "plain text"},
		{"terminal escapes", "bad\x1b[2J\x1b]0;title\x07\u009b31m\r\nrequest", "bad[2J]0;title31m request"},
		{"NUL and DEL inside a word", "tab\tand\x00nul\x7fdel", "tab andnuldel"},
		{"a multi-line body", "upload failed\nbucket refused the policy\r\n\r\n\tretry later\n",
			"upload failed bucket refused the policy retry later"},
		{"spaces around a line break collapse", "first line  \n  second", "first line second"},
		{"a break mixed with dropped controls", "a\r\x00\n\x1bb", "a b"},
		{"a form feed", "step1\fstep2", "step1 step2"},
		{"a vertical tab", "step1\vstep2", "step1 step2"},
		{"NEL", "step1\u0085step2", "step1 step2"},
		{"leading and trailing breaks are dropped", "\n\t error \r\n", "error"},
		{"spaces without a break are kept", "  two  spaces  ", "  two  spaces  "},
		{"Latin, Cyrillic and CJK", "ünïcode ✓ Ошибка сервера 服务器错误", "ünïcode ✓ Ошибка сервера 服务器错误"},
		{"emoji, with a ZWJ sequence and a variation selector", "done 🎉 👩‍💻 ❤️", "done 🎉 👩‍💻 ❤️"},
		{"empty", "", ""},
		{"only controls", "\r\n\x1b\t", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := util.StripControl(tt.in); got != tt.want {
				t.Errorf("StripControl(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestStripControlCap: StripControl reads at most 64 KiB, the spec's cap
// written out here so a change to the constant fails, cut at a rune
// boundary and marked with "…"; shorter text is not cut.
func TestStripControlCap(t *testing.T) {
	const capBytes = 64 << 10
	rows := []struct {
		name    string
		in      string
		wantCut bool
	}{
		{"1 MiB of 3-byte runes", strings.Repeat("服", (1<<20)/3), true},
		{"1 MiB of ASCII", strings.Repeat("a", 1<<20), true},
		{"1 MiB with line breaks", strings.Repeat("line\n", (1<<20)/5), true},
		{"exactly the cap", strings.Repeat("a", capBytes), false},
		{"one byte over the cap", strings.Repeat("a", capBytes+1), true},
		{"a 4-byte rune across the cap", strings.Repeat("a", capBytes-3) + "🎉" + strings.Repeat("b", 100), true},
		{"short", "short text", false},
		{"invalid UTF-8 past the cap", strings.Repeat("\x80", capBytes+10), true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			got := util.StripControl(row.in)
			cut := strings.HasSuffix(got, "…")
			if cut != row.wantCut {
				t.Fatalf("cut = %v, want %v (len %d)", cut, row.wantCut, len(got))
			}
			if !row.wantCut {
				if got != row.in {
					t.Errorf("a text within the cap changed: %d bytes in, %d out", len(row.in), len(got))
				}
				return
			}
			body := strings.TrimSuffix(got, "…")
			// Each byte read gives at most 3 bytes: an invalid byte becomes
			// U+FFFD.
			limit := capBytes
			if !utf8.ValidString(row.in) {
				limit = 3 * capBytes
			}
			if len(body) > limit {
				t.Errorf("output holds %d bytes before the marker, want at most %d", len(body), limit)
			}
			if len(body) < capBytes-utf8.UTFMax && !strings.Contains(row.in, "\n") && utf8.ValidString(row.in) {
				t.Errorf("output holds %d bytes, want close to the cap", len(body))
			}
			// A split rune would come out as U+FFFD, which is valid UTF-8.
			if utf8.ValidString(row.in) && strings.ContainsRune(got, utf8.RuneError) {
				t.Errorf("the cut split a rune")
			}
			if !strings.ContainsAny(row.in, "\n") && utf8.ValidString(row.in) && !strings.HasPrefix(row.in, body) {
				t.Errorf("the output is not a prefix of the input")
			}
		})
	}
}
