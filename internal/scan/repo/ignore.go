package repo

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
)

// maxIgnoreFileSize is the maximum allowed size for a .armisignore file (1 MB).
const maxIgnoreFileSize = 1 << 20

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
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf(".armisignore is a symlink (rejected): %s", path)
			}
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

func loadIgnoreFile(ignoreFilePath, repoRoot string) ([]gitignore.Pattern, error) {
	f, err := os.Open(ignoreFilePath) // #nosec G304 - ignore file path is constructed internally
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only file

	// Read up to maxIgnoreFileSize+1 to detect files exceeding the limit.
	limited := io.LimitReader(f, maxIgnoreFileSize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(data) > maxIgnoreFileSize {
		return nil, fmt.Errorf(".armisignore file too large (max %d bytes): %s", maxIgnoreFileSize, ignoreFilePath)
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
