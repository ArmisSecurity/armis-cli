// Package util provides utility functions for the CLI.
package util

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// SanitizePath cleans and validates a file path to prevent path traversal attacks.
func SanitizePath(p string) (string, error) {
	if p == "" {
		return "", errors.New("empty path")
	}

	// Check for ".." as a path component, not as a substring.
	// This allows valid filenames like "my..file.txt" while rejecting
	// path traversal attempts like "../etc/passwd" or "foo/../bar".
	segments := strings.FieldsFunc(p, func(r rune) bool {
		return r == '/' || r == '\\'
	})
	for _, seg := range segments {
		if seg == ".." {
			return "", errors.New("path traversal detected")
		}
	}

	cleaned := filepath.Clean(p)

	if cleaned == "" {
		return "", errors.New("invalid path")
	}

	return cleaned, nil
}

// SafeJoinPath joins basePath and relativePath, ensuring the result
// stays within basePath. Returns an error if relativePath attempts
// path traversal or is an absolute path.
func SafeJoinPath(basePath, relativePath string) (string, error) {
	if relativePath == "" {
		return "", errors.New("empty relative path")
	}

	// Reject absolute paths
	if filepath.IsAbs(relativePath) {
		return "", errors.New("absolute path not allowed")
	}

	// Clean both paths
	cleanBase := filepath.Clean(basePath)
	cleanRel := filepath.Clean(relativePath)

	// Check for path traversal in the relative path after cleaning
	if cleanRel == ".." || strings.HasPrefix(cleanRel, ".."+string(filepath.Separator)) {
		return "", errors.New("path traversal detected")
	}

	// Join paths
	joined := filepath.Join(cleanBase, cleanRel)

	// Final verification: ensure joined path starts with base path
	absBase, err := filepath.Abs(cleanBase)
	if err != nil {
		return "", fmt.Errorf("failed to resolve base path: %w", err)
	}
	absJoined, err := filepath.Abs(joined)
	if err != nil {
		return "", fmt.Errorf("failed to resolve joined path: %w", err)
	}

	// Ensure the joined path is within the base directory
	// Use filepath.Rel to verify containment - this correctly handles root path "/"
	rel, err := filepath.Rel(absBase, absJoined)
	if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return "", errors.New("path escapes base directory")
	}

	return joined, nil
}
