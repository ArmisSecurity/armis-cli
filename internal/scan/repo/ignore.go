package repo

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
)

// maxIgnoreFileSize is the maximum allowed size for a .armisignore file (1 MB).
const maxIgnoreFileSize = 1 << 20

// utf8BOM is the byte order mark that some editors prepend to UTF-8 files.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// IgnoreMatcher matches files against ignore patterns.
type IgnoreMatcher struct {
	patterns []gitignore.Pattern
}

// LoadIgnorePatterns loads ignore patterns from .armisignore files in the repository.
// This is a backward-compatible wrapper around LoadArmisIgnore that discards directives.
func LoadIgnorePatterns(repoRoot string) (*IgnoreMatcher, error) {
	matcher, _, err := LoadArmisIgnore(repoRoot)
	return matcher, err
}

// LoadSuppressionConfig loads only suppression directives from the root .armisignore file
// without walking the entire repository tree. Use this in targeted scan modes (--include-files,
// --changed) where the IgnoreMatcher is not needed for tar filtering.
func LoadSuppressionConfig(repoRoot string) (*SuppressionConfig, error) {
	if !filepath.IsAbs(repoRoot) {
		return nil, fmt.Errorf("repoRoot must be an absolute path, got: %s", repoRoot)
	}
	rootIgnorePath := filepath.Join(filepath.Clean(repoRoot), ".armisignore") // #nosec G304

	info, err := os.Lstat(rootIgnorePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf(".armisignore is a symlink (rejected): %s", rootIgnorePath)
	}

	_, directives, warnings, parseErr := parseArmisIgnoreFile(rootIgnorePath, repoRoot, true)
	if parseErr != nil {
		return nil, parseErr
	}

	for _, w := range warnings {
		cli.PrintWarningf(".armisignore: %s", w)
	}

	if len(directives) == 0 {
		return nil, nil
	}

	config := NewSuppressionConfig()
	for i := range directives {
		config.Add(directives[i])
	}
	return config, nil
}

// LoadArmisIgnore loads both path patterns and suppression directives from .armisignore files.
// Path patterns are collected from all .armisignore files (root and nested).
// Suppression directives are only collected from the root .armisignore file.
// Warnings for invalid directives are emitted to stderr via cli.PrintWarningf.
func LoadArmisIgnore(repoRoot string) (*IgnoreMatcher, *SuppressionConfig, error) {
	var allPatterns []gitignore.Pattern
	config := NewSuppressionConfig()
	// armis:ignore cwe:73 reason:filepath.Join with hardcoded ".armisignore" filename; repoRoot is from validated CLI arg
	rootIgnorePath := filepath.Join(repoRoot, ".armisignore")

	err := filepath.Walk(repoRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() && shouldSkipDir(info.Name()) {
			return filepath.SkipDir
		}

		if !info.IsDir() && info.Name() == ".armisignore" {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf(".armisignore is a symlink (rejected): %s", path)
			}

			isRoot := path == rootIgnorePath
			patterns, directives, warnings, parseErr := parseArmisIgnoreFile(path, repoRoot, isRoot)
			if parseErr != nil {
				return parseErr
			}

			allPatterns = append(allPatterns, patterns...)

			if isRoot {
				for i := range directives {
					config.Add(directives[i])
				}
			}

			for _, w := range warnings {
				cli.PrintWarningf(".armisignore: %s", w)
			}
		}

		return nil
	})

	if err != nil {
		return nil, nil, err
	}

	matcher := &IgnoreMatcher{
		patterns: allPatterns,
	}

	if config.IsEmpty() {
		return matcher, nil, nil
	}
	return matcher, config, nil
}

// parseArmisIgnoreFile reads and parses a single .armisignore file.
// When isRoot is true, directive lines are parsed and returned.
// When isRoot is false, directive-like lines are still treated as path patterns (backward compat).
// armis:ignore cwe:73 reason:ignoreFilePath constructed internally via filepath.Walk, not user-controlled
func parseArmisIgnoreFile(ignoreFilePath, repoRoot string, isRoot bool) ([]gitignore.Pattern, []SuppressionDirective, []string, error) {
	f, err := os.Open(ignoreFilePath) // #nosec G304 - ignore file path is constructed internally
	if err != nil {
		return nil, nil, nil, err
	}
	defer f.Close() //nolint:errcheck // read-only file

	limited := io.LimitReader(f, maxIgnoreFileSize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(data) > maxIgnoreFileSize {
		return nil, nil, nil, fmt.Errorf(".armisignore file too large (max %d bytes): %s", maxIgnoreFileSize, ignoreFilePath)
	}

	data = bytes.TrimPrefix(data, utf8BOM)

	ignoreDir := filepath.Dir(ignoreFilePath)
	relDir, err := filepath.Rel(repoRoot, ignoreDir)
	if err != nil {
		return nil, nil, nil, err
	}

	var domain []string
	if relDir != "." {
		domain = strings.Split(relDir, string(filepath.Separator))
	}

	content := strings.TrimSuffix(string(data), "\n")
	lines := strings.Split(content, "\n")

	var warnings []string
	if len(lines) > maxIgnoreFileLines {
		warnings = append(warnings, fmt.Sprintf("file exceeds %d lines, truncated: %s", maxIgnoreFileLines, ignoreFilePath))
		lines = lines[:maxIgnoreFileLines]
	}

	patterns := make([]gitignore.Pattern, 0, len(lines))
	var directives []SuppressionDirective

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if isRoot && hasDirectivePrefix(trimmed) {
			directive, isDirective, warning := parseDirectiveLine(trimmed)
			if warning != "" {
				warnings = append(warnings, warning)
			}
			if isDirective {
				directives = append(directives, *directive)
			}
			continue
		}

		pattern := gitignore.ParsePattern(trimmed, domain)
		patterns = append(patterns, pattern)
	}

	return patterns, directives, warnings, nil
}

// Match returns true if the path matches any ignore pattern.
func (m *IgnoreMatcher) Match(path string, isDir bool) bool {
	if m == nil || len(m.patterns) == 0 {
		return false
	}

	normalizedPath := filepath.FromSlash(path)
	pathParts := strings.Split(normalizedPath, string(filepath.Separator))

	matcher := gitignore.NewMatcher(m.patterns)
	return matcher.Match(pathParts, isDir)
}

func shouldSkipDir(name string) bool {
	skipDirs := []string{
		".git", ".svn", ".hg",
	}
	for _, dir := range skipDirs {
		if name == dir {
			return true
		}
	}
	return false
}
