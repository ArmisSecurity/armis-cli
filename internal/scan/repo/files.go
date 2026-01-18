// Package repo provides repository scanning functionality.
package repo

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/util"
)

// FileList represents a list of files to be scanned.
type FileList struct {
	files    []string
	repoRoot string
}

// ParseFileList parses file paths from the --include-files flag.
// It accepts both relative paths (to repoRoot) and absolute paths,
// normalizing all to relative paths.
func ParseFileList(repoRoot string, files []string) (*FileList, error) {
	absRoot, err := filepath.Abs(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve repo root: %w", err)
	}

	fl := &FileList{repoRoot: absRoot}
	for _, f := range files {
		if err := fl.addFile(f); err != nil {
			return nil, err
		}
	}
	return fl, nil
}

func (fl *FileList) addFile(path string) error {
	if path == "" {
		return nil // Skip empty paths
	}

	// Normalize path separators
	path = filepath.FromSlash(path)

	// Convert absolute paths to relative
	if filepath.IsAbs(path) {
		// Check if absolute path is within repo root before converting
		if !strings.HasPrefix(path, fl.repoRoot+string(filepath.Separator)) && path != fl.repoRoot {
			return fmt.Errorf("absolute path %q is outside repository root %q", path, fl.repoRoot)
		}
		rel, err := filepath.Rel(fl.repoRoot, path)
		if err != nil {
			return fmt.Errorf("cannot make path relative to repo: %s", path)
		}
		path = rel
	}

	// Validate path doesn't escape repo root using SafeJoinPath
	if _, err := util.SafeJoinPath(fl.repoRoot, path); err != nil {
		return fmt.Errorf("invalid path %q: %w", path, err)
	}

	fl.files = append(fl.files, path)
	return nil
}

// Files returns the validated list of relative file paths.
func (fl *FileList) Files() []string {
	return fl.files
}

// RepoRoot returns the absolute path to the repository root.
func (fl *FileList) RepoRoot() string {
	return fl.repoRoot
}

// ValidateExistence checks which files exist and returns warnings for missing files.
func (fl *FileList) ValidateExistence() (existing []string, warnings []string) {
	for _, f := range fl.files {
		absPath := filepath.Join(fl.repoRoot, f)
		info, err := os.Stat(absPath)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("file not found: %s", f))
			continue
		}
		// Skip directories - we only scan files
		if info.IsDir() {
			warnings = append(warnings, fmt.Sprintf("skipping directory: %s", f))
			continue
		}
		existing = append(existing, f)
	}
	return
}
