// Package output provides formatters and utilities for CLI output.
package output

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// osWindows is used for runtime.GOOS comparisons.
const osWindows = "windows"

// FileOutput manages writing formatted output to a file.
type FileOutput struct {
	file *os.File
}

// dangerousPaths contains paths that should never be written to by the CLI.
// These are system-critical paths where accidental writes could cause system damage.
var dangerousPaths = map[string]bool{
	// Unix/Linux critical paths
	"/etc/passwd":  true,
	"/etc/shadow":  true,
	"/etc/sudoers": true,
	"/etc/hosts":   true,
	// Windows critical paths (normalized to forward slashes for comparison)
	"c:/windows/system32/config/sam":      true,
	"c:/windows/system32/config/system":   true,
	"c:/windows/system32/config/security": true,
}

// dangerousDirs contains directory prefixes that should be restricted.
var dangerousDirs = []string{
	"/etc/",
	"/boot/",
	"/proc/",
	"/sys/",
	"/dev/",
}

// validateOutputPath checks if the path is safe for writing output.
// It rejects known dangerous system paths as a defense-in-depth measure.
//
// Note: This is a CLI tool that runs with user privileges, so the user could
// write to these paths via their shell anyway. This validation is purely
// defensive to prevent accidental damage from typos or automation errors.
func validateOutputPath(absPath string) error {
	// Normalize path for comparison (lowercase on Windows, forward slashes)
	normalizedPath := absPath
	if runtime.GOOS == osWindows {
		normalizedPath = strings.ToLower(filepath.ToSlash(absPath))
	}

	// Check exact dangerous paths
	checkPath := normalizedPath
	if runtime.GOOS != osWindows {
		checkPath = absPath
	}
	if dangerousPaths[checkPath] {
		return fmt.Errorf("refusing to write to system-critical path: %s", absPath)
	}

	// Check dangerous directory prefixes (Unix only)
	if runtime.GOOS != osWindows {
		for _, dir := range dangerousDirs {
			if strings.HasPrefix(absPath, dir) {
				return fmt.Errorf("refusing to write to system directory: %s", absPath)
			}
		}
	}

	return nil
}

// NewFileOutput creates an output writer targeting a file.
// It creates parent directories if they don't exist.
// The returned FileOutput should be closed after use.
//
// Security: This validates the path against known dangerous system paths, then
// accepts any other user-specified path from the --output CLI flag. This is
// intentional - CLI tools run with the user's own privileges, so the user can
// already write to any path they have access to via their shell. There is no
// privilege escalation or sandbox escape possible.
func NewFileOutput(path string) (*FileOutput, error) {
	if path == "" {
		return nil, errors.New("output path cannot be empty")
	}

	// Resolve to absolute path and clean it to normalize any traversal sequences
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve output path %s: %w", path, err)
	}
	cleanPath := filepath.Clean(absPath)

	// Validate path against dangerous system paths (defense in depth)
	if err := validateOutputPath(cleanPath); err != nil {
		return nil, err
	}

	// Create parent directories if needed
	dir := filepath.Dir(cleanPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return nil, fmt.Errorf("failed to create output directory %s: %w", dir, err)
		}
	}

	// Create or truncate the output file with restricted permissions (owner read/write only).
	//
	// Security note (CWE-73 / path injection):
	// This code intentionally accepts user-controlled paths from the --output CLI flag.
	// This is NOT a vulnerability because:
	//   1. This is a CLI tool that runs with the user's own privileges
	//   2. The user already has shell access and can write anywhere (e.g., `cat > /any/path`)
	//   3. There is no privilege escalation or sandbox escape possible
	//   4. Dangerous system paths (/etc/*, /boot/*, etc.) are blocked above
	//
	// Static analyzers flag this as CWE-73 because they see user-input → file-write,
	// but this pattern is standard for CLI tools (like `cat`, `tee`, `cp`, etc.).
	// CodeQL/GHAS alerts for this should be dismissed as "Won't fix" in the UI.
	//
	// #nosec G304 -- CLI tool with explicit user-controlled --output flag; no privilege escalation.
	file, err := os.OpenFile(cleanPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file %s: %w", cleanPath, err)
	}

	// Best-effort: ensure restrictive permissions even if the file already existed.
	// On Unix, OpenFile's mode is ignored for existing files, so explicitly chmod.
	// Ignore errors here to avoid breaking on platforms/filesystems that don't support this.
	_ = os.Chmod(cleanPath, 0600)

	return &FileOutput{file: file}, nil
}

// Writer returns the underlying io.Writer for the file.
func (f *FileOutput) Writer() io.Writer {
	return f.file
}

// Close closes the underlying file.
func (f *FileOutput) Close() error {
	if f.file != nil {
		return f.file.Close()
	}
	return nil
}

// FormatFromExtension returns the output format based on file extension.
// Returns empty string if the extension is not recognized.
//
// Supported extensions:
//   - .json -> "json"
//   - .sarif -> "sarif"
//   - .xml -> "junit"
//
// For unrecognized extensions, returns empty string to indicate
// the format should be taken from the --format flag.
func FormatFromExtension(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		return "json"
	case ".sarif":
		return "sarif"
	case ".xml":
		return "junit"
	default:
		return ""
	}
}
