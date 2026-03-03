// Package output provides formatters and utilities for CLI output.
package output

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// FileOutput manages writing formatted output to a file.
type FileOutput struct {
	file *os.File
}

// NewFileOutput creates an output writer targeting a file.
// It creates parent directories if they don't exist.
// The returned FileOutput should be closed after use.
func NewFileOutput(path string) (*FileOutput, error) {
	// Resolve to absolute path and clean it to prevent path traversal
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve output path %s: %w", path, err)
	}
	cleanPath := filepath.Clean(absPath)

	// Create parent directories if needed
	dir := filepath.Dir(cleanPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return nil, fmt.Errorf("failed to create output directory %s: %w", dir, err)
		}
	}

	// Create or truncate the output file
	// #nosec G304 -- path is cleaned and resolved to absolute; user explicitly specifies --output
	file, err := os.Create(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file %s: %w", cleanPath, err)
	}

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
