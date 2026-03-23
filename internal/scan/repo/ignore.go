package repo

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
)

// IgnoreMatcher matches files against ignore patterns.
type IgnoreMatcher struct {
	patterns []gitignore.Pattern
	domain   []string
}

// LoadIgnorePatterns loads ignore patterns from .armisignore files in the repository.
func LoadIgnorePatterns(repoRoot string) (*IgnoreMatcher, error) {
	var allPatterns []gitignore.Pattern

	err := filepath.Walk(repoRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() && shouldSkipDir(info.Name()) {
			return filepath.SkipDir
		}

		if !info.IsDir() && info.Name() == ".armisignore" {
			patterns, err := loadIgnoreFile(path, repoRoot)
			if err != nil {
				return err
			}
			allPatterns = append(allPatterns, patterns...)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	domain := strings.Split(repoRoot, string(filepath.Separator))
	return &IgnoreMatcher{
		patterns: allPatterns,
		domain:   domain,
	}, nil
}

// maxIgnoreFileSize is the maximum allowed size for .armisignore files (1MB).
// Ignore files are typically a few KB at most; anything larger is likely an error.
const maxIgnoreFileSize = 1 * 1024 * 1024

func loadIgnoreFile(ignoreFilePath, repoRoot string) ([]gitignore.Pattern, error) {
	info, err := os.Stat(ignoreFilePath)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxIgnoreFileSize {
		return nil, fmt.Errorf(".armisignore file %s is too large (%d bytes, max %d)", ignoreFilePath, info.Size(), maxIgnoreFileSize)
	}

	data, err := os.ReadFile(ignoreFilePath) // #nosec G304 - ignore file path is constructed internally
	if err != nil {
		return nil, err
	}

	ignoreDir := filepath.Dir(ignoreFilePath)
	relDir, err := filepath.Rel(repoRoot, ignoreDir)
	if err != nil {
		return nil, err
	}

	var domain []string
	if relDir != "." {
		domain = strings.Split(relDir, string(filepath.Separator))
	}

	lines := strings.Split(string(data), "\n")
	patterns := make([]gitignore.Pattern, 0, len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		pattern := gitignore.ParsePattern(line, domain)
		patterns = append(patterns, pattern)
	}

	return patterns, nil
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
