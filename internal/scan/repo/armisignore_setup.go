package repo

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// IgnoreSummary is what a scan's .armisignore files hold, so that a
// first-time project setup can skip the questions they already answer.
type IgnoreSummary struct {
	// Root is the scanned folder (absolute), where the root .armisignore is.
	Root string
	// RootFile: the root .armisignore exists, and has RootLines lines.
	RootFile  bool
	RootLines int
	// Paths: some .armisignore under Root has a path pattern.
	Paths bool
	// Severities, Categories and CWEs: the root file has a directive of the
	// type (directives are read from the root file only).
	Severities bool
	Categories bool
	CWEs       bool
}

// summarizeIgnore describes the .armisignore files the scan loaded.
func summarizeIgnore(root string, matcher *IgnoreMatcher, cfg *SuppressionConfig) IgnoreSummary {
	s := IgnoreSummary{Root: root, Paths: matcher != nil && len(matcher.patterns) > 0}
	if cfg != nil {
		s.Severities = len(cfg.Severities) > 0
		s.Categories = len(cfg.Categories) > 0
		s.CWEs = len(cfg.CWEs) > 0
	}
	if data, err := readRootArmisignore(root); err == nil && data != nil {
		s.RootFile, s.RootLines = true, countLines(data)
	}
	return s
}

// readRootArmisignore reads root's .armisignore, at most maxIgnoreFileSize
// bytes; nil (and no error) when there is none.
func readRootArmisignore(root string) ([]byte, error) {
	// armis:ignore cwe:73 reason:filepath.Join with the constant ".armisignore" name; root is the scanned folder, validated by SanitizePath and made absolute by Scan
	path := filepath.Join(filepath.Clean(root), ".armisignore")
	f, err := os.Open(path) // #nosec G304 - the constant file name in the scanned folder
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only file
	data, err := io.ReadAll(io.LimitReader(f, maxIgnoreFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxIgnoreFileSize {
		return nil, fmt.Errorf(".armisignore file too large (max %d bytes): %s", maxIgnoreFileSize, path)
	}
	return data, nil
}

// countLines counts data's lines, a last line without its line end included.
func countLines(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	n := bytes.Count(data, []byte("\n"))
	if !bytes.HasSuffix(data, []byte("\n")) {
		n++
	}
	return n
}

// WriteArmisignoreBlock writes a first-time setup's lines to root's
// .armisignore: it creates the file, or appends the lines after a blank line,
// and never changes a line already there. It reports whether it created the
// file. Like the loader, it refuses a .armisignore that is a symlink or not a
// regular file, and it keeps the file within the loader's limits.
func WriteArmisignoreBlock(root string, lines []string) (created bool, err error) {
	if len(lines) == 0 {
		return false, nil
	}
	// armis:ignore cwe:73 reason:filepath.Join with the constant ".armisignore" name; root is the scanned folder, validated by SanitizePath and made absolute by Scan
	path := filepath.Join(filepath.Clean(root), ".armisignore")
	info, statErr := os.Lstat(path)
	switch {
	case statErr == nil && info.Mode()&os.ModeSymlink != 0:
		return false, fmt.Errorf(".armisignore is a symlink (refused): %s", path)
	case statErr == nil && !info.Mode().IsRegular():
		return false, fmt.Errorf(".armisignore is not a regular file: %s", path)
	case statErr != nil && !os.IsNotExist(statErr):
		return false, statErr
	}
	created = statErr != nil

	block := strings.Join(lines, "\n") + "\n"
	if !created {
		existing, err := readRootArmisignore(root)
		if err != nil {
			return false, err
		}
		if len(existing) > 0 {
			prefix := "\n"
			if !bytes.HasSuffix(existing, []byte("\n")) {
				prefix = "\n\n"
			}
			block = prefix + block
		}
		if total := countLines(existing) + len(lines) + 1; total > maxIgnoreFileLines {
			return false, fmt.Errorf(".armisignore would have %d lines; the CLI reads at most %d", total, maxIgnoreFileLines)
		}
		if len(existing)+len(block) > maxIgnoreFileSize {
			return false, fmt.Errorf(".armisignore would be larger than %d bytes", maxIgnoreFileSize)
		}
	}

	// #nosec G302 G304 -- a repository file meant to be committed, as readable as .gitignore; the constant name in the scanned folder
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return false, err
	}
	if _, err := f.WriteString(block); err != nil {
		_ = f.Close()
		return false, err
	}
	return created, f.Close()
}
