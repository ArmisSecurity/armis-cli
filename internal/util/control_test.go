package util_test

import (
	"testing"

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
