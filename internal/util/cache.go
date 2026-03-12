// Package util provides shared utilities for the CLI.
package util

import (
	"os"
	"path/filepath"
)

const (
	// CacheDirName is the subdirectory name for CLI cache files.
	// Used by both update checker and region cache.
	CacheDirName = "armis-cli"
)

// GetCacheDir returns the validated path to the CLI's cache directory.
// Returns empty string if the cache directory cannot be determined or validated.
// The directory is NOT created by this function - callers should create it if needed.
//
// Default location: ~/.cache/armis-cli (or platform equivalent)
func GetCacheDir() string {
	userCacheDir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}

	cacheDir := filepath.Join(userCacheDir, CacheDirName)

	// Validate path to prevent traversal attacks (CWE-73)
	sanitized, err := SanitizePath(cacheDir)
	if err != nil {
		return ""
	}

	return sanitized
}

// GetCacheFilePath returns the validated path to a cache file.
// Returns empty string if the path cannot be determined or validated.
func GetCacheFilePath(filename string) string {
	cacheDir := GetCacheDir()
	if cacheDir == "" {
		return ""
	}

	filePath := filepath.Join(cacheDir, filename)

	// Re-validate the full path (filename could contain traversal attempts)
	sanitized, err := SanitizePath(filePath)
	if err != nil {
		return ""
	}

	return sanitized
}
