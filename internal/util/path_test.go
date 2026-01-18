package util_test

import (
	"os"
	"path/filepath"
	"runtime"
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
			name:    "dot path",
			input:   ".",
			wantErr: false,
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
			errSubstr: "path traversal detected",
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

func TestSafeJoinPath(t *testing.T) {
	// Create a real temporary directory for tests that need an existing base path
	baseDir := t.TempDir()

	tests := []struct {
		name         string
		basePath     string
		relativePath string
		wantErr      bool
		errSubstr    string
	}{
		{
			name:         "valid simple path",
			basePath:     baseDir,
			relativePath: "file.txt",
			wantErr:      false,
		},
		{
			name:         "valid nested path",
			basePath:     baseDir,
			relativePath: "subdir/file.txt",
			wantErr:      false,
		},
		{
			name:         "empty relative path",
			basePath:     baseDir,
			relativePath: "",
			wantErr:      true,
			errSubstr:    "empty relative path",
		},
		{
			name:     "absolute path rejected",
			basePath: baseDir,
			relativePath: func() string {
				if runtime.GOOS == "windows" {
					return `C:\Windows\System32`
				}
				return "/etc/passwd"
			}(),
			wantErr:   true,
			errSubstr: "absolute path not allowed",
		},
		{
			name:         "path traversal with double dots",
			basePath:     baseDir,
			relativePath: "../etc/passwd",
			wantErr:      true,
			errSubstr:    "path traversal detected",
		},
		{
			name:         "path traversal with multiple double dots",
			basePath:     baseDir,
			relativePath: "../../../etc/passwd",
			wantErr:      true,
			errSubstr:    "path traversal detected",
		},
		{
			name:         "path traversal hidden in path",
			basePath:     baseDir,
			relativePath: "subdir/../../etc/passwd",
			wantErr:      true,
			errSubstr:    "path traversal detected",
		},
		{
			name:         "just double dots",
			basePath:     baseDir,
			relativePath: "..",
			wantErr:      true,
			errSubstr:    "path traversal detected",
		},
		{
			name:         "valid path with current dir",
			basePath:     baseDir,
			relativePath: "./file.txt",
			wantErr:      false,
		},
		{
			name:         "valid path with spaces",
			basePath:     baseDir,
			relativePath: "my file.txt",
			wantErr:      false,
		},
		// Root base path tests - regression tests for CWE-22 fix
		{
			name:         "root base with simple file",
			basePath:     "/",
			relativePath: "etc/passwd",
			wantErr:      false,
		},
		{
			name:         "root base with nested path",
			basePath:     "/",
			relativePath: "home/user/file.txt",
			wantErr:      false,
		},
		{
			name:         "root base with path traversal",
			basePath:     "/",
			relativePath: "../something",
			wantErr:      true,
			errSubstr:    "path traversal detected",
		},
		{
			name:         "root base exact match",
			basePath:     "/",
			relativePath: ".",
			wantErr:      false,
		},
		// New tests for directory verification
		{
			name:         "non-existent base path",
			basePath:     "/non/existent/path",
			relativePath: "file.txt",
			wantErr:      true,
			errSubstr:    "cannot access base path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := util.SafeJoinPath(tt.basePath, tt.relativePath)
			if tt.wantErr {
				if err == nil {
					t.Errorf("util.SafeJoinPath(%q, %q) expected error containing %q, got nil (result: %q)", tt.basePath, tt.relativePath, tt.errSubstr, result)
				} else if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("util.SafeJoinPath(%q, %q) expected error containing %q, got %q", tt.basePath, tt.relativePath, tt.errSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("util.SafeJoinPath(%q, %q) unexpected error: %v", tt.basePath, tt.relativePath, err)
				}
				if result == "" {
					t.Errorf("util.SafeJoinPath(%q, %q) returned empty result", tt.basePath, tt.relativePath)
				}
			}
		})
	}
}

func TestSafeJoinPathWithFile(t *testing.T) {
	// Test that base path must be a directory, not a file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "file.txt")
	if err := os.WriteFile(tmpFile, []byte("content"), 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	_, err := util.SafeJoinPath(tmpFile, "something.txt")
	if err == nil {
		t.Error("SafeJoinPath should reject a file as base path")
	}
	if !strings.Contains(err.Error(), "base path must be a directory") {
		t.Errorf("Expected error about directory, got: %v", err)
	}
}

func TestSafeJoinPathResultsContainedInBase(t *testing.T) {
	// Create a real temporary directory for tests
	baseDir := t.TempDir()

	tests := []struct {
		name         string
		relativePath string
		wantSuffix   string
	}{
		{
			name:         "simple file",
			relativePath: "file.txt",
			wantSuffix:   "file.txt",
		},
		{
			name:         "nested path",
			relativePath: "subdir/file.txt",
			wantSuffix:   "subdir/file.txt",
		},
		{
			name:         "current dir prefix cleaned",
			relativePath: "./subdir/file.txt",
			wantSuffix:   "subdir/file.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := util.SafeJoinPath(baseDir, tt.relativePath)
			if err != nil {
				t.Fatalf("util.SafeJoinPath(%q, %q) unexpected error: %v", baseDir, tt.relativePath, err)
			}
			normalizedResult := filepath.ToSlash(result)
			if !strings.HasSuffix(normalizedResult, tt.wantSuffix) {
				t.Errorf("util.SafeJoinPath(%q, %q) = %q, want suffix %q", baseDir, tt.relativePath, normalizedResult, tt.wantSuffix)
			}
			normalizedBase := filepath.ToSlash(baseDir)
			if !strings.HasPrefix(normalizedResult, normalizedBase) {
				t.Errorf("util.SafeJoinPath(%q, %q) = %q, should start with base %q", baseDir, tt.relativePath, normalizedResult, normalizedBase)
			}
		})
	}
}
