package util_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/util"
)

func TestSanitizePath(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid simple path",
			input:   "test.txt",
			wantErr: false,
		},
		{
			name:    "valid relative path",
			input:   "dir/file.txt",
			wantErr: false,
		},
		{
			name:    "valid path with redundant separators",
			input:   "dir//file.txt",
			wantErr: false,
		},
		{
			name:      "empty path",
			input:     "",
			wantErr:   true,
			errSubstr: "empty path",
		},
		{
			name:      "dot path",
			input:     ".",
			wantErr:   true,
			errSubstr: "invalid path",
		},
		{
			name:      "path traversal with double dots",
			input:     "../etc/passwd",
			wantErr:   true,
			errSubstr: "path traversal detected",
		},
		{
			name:      "path traversal in middle",
			input:     "dir/../../../etc/passwd",
			wantErr:   true,
			errSubstr: "path traversal detected",
		},
		{
			name:      "path traversal at end",
			input:     "dir/..",
			wantErr:   true,
			errSubstr: "invalid path",
		},
		{
			name:    "valid absolute path",
			input:   "/tmp/test.txt",
			wantErr: false,
		},
		{
			name:    "path with spaces",
			input:   "my file.txt",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := util.SanitizePath(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("util.SanitizePath(%q) expected error containing %q, got nil", tt.input, tt.errSubstr)
				} else if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("util.SanitizePath(%q) expected error containing %q, got %q", tt.input, tt.errSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("util.SanitizePath(%q) unexpected error: %v", tt.input, err)
				}
				if result == "" {
					t.Errorf("util.SanitizePath(%q) returned empty result", tt.input)
				}
			}
		})
	}
}

func TestSanitizePathCleaning(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "removes redundant separators",
			input:    "dir//file.txt",
			expected: "dir/file.txt",
		},
		{
			name:     "removes trailing separator",
			input:    "dir/",
			expected: "dir",
		},
		{
			name:     "preserves single file",
			input:    "file.txt",
			expected: "file.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := util.SanitizePath(tt.input)
			if err != nil {
				t.Fatalf("util.SanitizePath(%q) unexpected error: %v", tt.input, err)
			}
			normalizedResult := filepath.ToSlash(result)
			if normalizedResult != tt.expected {
				t.Errorf("util.SanitizePath(%q) = %q, want %q", tt.input, normalizedResult, tt.expected)
			}
		})
	}
}
