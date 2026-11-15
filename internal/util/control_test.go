package util_test

import (
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/util"
)

func TestStripControl(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"plain text", "plain text"},
		{"bad\x1b[2J\x1b]0;title\x07\u009b31m\r\nrequest", "bad[2J]0;title31mrequest"},
		{"tab\tand\x00nul\x7fdel", "tabandnuldel"},
		{"ünïcode ✓", "ünïcode ✓"},
	}
	for _, tt := range tests {
		if got := util.StripControl(tt.in); got != tt.want {
			t.Errorf("StripControl(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
