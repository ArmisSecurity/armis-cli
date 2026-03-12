package util

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGetCacheDir(t *testing.T) {
	dir := GetCacheDir()

	// Should not be empty (unless running in a very unusual environment)
	if dir == "" {
		t.Skip("Unable to determine cache directory (may be running in unusual environment)")
	}

	// Should end with our cache dir name
	if !strings.HasSuffix(dir, CacheDirName) {
		t.Errorf("Expected cache dir to end with %q, got %q", CacheDirName, dir)
	}

	// Should be an absolute path
	if !filepath.IsAbs(dir) {
		t.Errorf("Expected absolute path, got %q", dir)
	}
}

func TestGetCacheFilePath(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		wantEnd  string
	}{
		{
			name:     "simple filename",
			filename: "test.json",
			wantEnd:  filepath.Join(CacheDirName, "test.json"),
		},
		{
			name:     "another filename",
			filename: "region-cache.json",
			wantEnd:  filepath.Join(CacheDirName, "region-cache.json"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := GetCacheFilePath(tt.filename)
			if path == "" {
				t.Skip("Unable to determine cache file path")
			}

			if !strings.HasSuffix(path, tt.wantEnd) {
				t.Errorf("GetCacheFilePath(%q) = %q, want suffix %q", tt.filename, path, tt.wantEnd)
			}

			if !filepath.IsAbs(path) {
				t.Errorf("Expected absolute path, got %q", path)
			}
		})
	}
}

func TestGetCacheFilePath_SafeFilenames(t *testing.T) {
	// This function is designed to be called with safe, constant filenames.
	// The security boundary is enforced by rejecting absolute paths and
	// path separators in the filename parameter.

	tests := []struct {
		name         string
		filename     string
		wantContains string
		wantEmpty    bool
	}{
		{"simple json file", "test.json", "test.json", false},
		{"hyphenated name", "region-cache.json", "region-cache.json", false},
		// Absolute paths are rejected (CWE-22: filepath.Join would discard cacheDir)
		{"absolute path rejected", "/etc/passwd", "", true},
		// Path separators are rejected to ensure filename is a simple name
		{"path with forward slash rejected", "foo/bar.json", "", true},
		{"path with backslash rejected", "foo\\bar.json", "", true},
		// Traversal attempts are rejected by SanitizePath
		{"traversal rejected", "..\\secret.txt", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := GetCacheFilePath(tt.filename)

			if tt.wantEmpty {
				if path != "" {
					t.Errorf("GetCacheFilePath(%q) = %q, want empty (rejected)", tt.filename, path)
				}
				return
			}

			if path == "" {
				t.Errorf("GetCacheFilePath(%q) returned empty, want non-empty", tt.filename)
				return
			}
			if !strings.Contains(path, tt.wantContains) {
				t.Errorf("GetCacheFilePath(%q) = %q, want to contain %q", tt.filename, path, tt.wantContains)
			}
			// Verify result is within cache directory
			cacheDir := GetCacheDir()
			if !strings.HasPrefix(path, cacheDir) {
				t.Errorf("GetCacheFilePath(%q) = %q, not within cache dir %q", tt.filename, path, cacheDir)
			}
		})
	}
}

func TestCacheDirName_Constant(t *testing.T) {
	// Verify the constant matches expected value
	if CacheDirName != "armis-cli" {
		t.Errorf("CacheDirName = %q, want %q", CacheDirName, "armis-cli")
	}
}

func TestGetCacheDir_Idempotent(t *testing.T) {
	// Multiple calls should return the same path
	dir1 := GetCacheDir()
	dir2 := GetCacheDir()

	if dir1 != dir2 {
		t.Errorf("GetCacheDir() not idempotent: %q != %q", dir1, dir2)
	}
}

func TestGetCacheDir_UserCacheDir(t *testing.T) {
	// Verify our cache dir is under the user's cache directory
	userCacheDir, err := os.UserCacheDir()
	if err != nil {
		t.Skip("os.UserCacheDir() not available")
	}

	dir := GetCacheDir()
	if dir == "" {
		t.Skip("GetCacheDir() returned empty")
	}

	expected := filepath.Join(userCacheDir, CacheDirName)
	// Compare cleaned paths
	if filepath.Clean(dir) != filepath.Clean(expected) {
		t.Errorf("GetCacheDir() = %q, want %q", dir, expected)
	}
}
