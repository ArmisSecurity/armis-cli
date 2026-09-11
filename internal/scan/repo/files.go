// Package repo provides repository scanning functionality.
package repo

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/util"
)

// MaxFiles is the maximum number of files that can be specified via --include-files.
// This limit prevents resource exhaustion from extremely large file lists.
const MaxFiles = 1000

// ErrTooManyFiles is returned when a selection holds more than MaxFiles distinct
// files. It is a sentinel so a caller can tell an over-large selection apart
// from a rejected path and say something useful about the difference.
var ErrTooManyFiles = errors.New("too many files")

// FileList represents a list of files to be scanned.
type FileList struct {
	files    []string
	seen     map[string]struct{}
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

	fl := &FileList{repoRoot: absRoot, seen: make(map[string]struct{}, len(files))}
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

	// Normalize path separators, then lexically clean the path so that "a.go",
	// "./a.go" and "dir/../a.go" are one key. Without this the de-duplication
	// below compares spellings rather than files. Clean cannot escape the root --
	// a result that starts with ".." is still rejected by SafeJoinPath below.
	path = filepath.Clean(filepath.FromSlash(path))

	// Convert absolute paths to relative
	if filepath.IsAbs(path) {
		rel, err := fl.relativeToRoot(path)
		if err != nil {
			return err
		}
		path = rel
	}

	// Validate path doesn't escape repo root using SafeJoinPath
	// armis:ignore cwe:22 reason:this IS the path traversal prevention check (SafeJoinPath validates containment)
	if _, err := util.SafeJoinPath(fl.repoRoot, path); err != nil {
		return fmt.Errorf("invalid path %q: %w", path, err)
	}

	// De-duplicate on the normalized path. Two spellings of one file are one
	// file, so a repeat must not consume the MaxFiles budget: a caller that
	// merges two selections -- --include-files plus the filenames a tool appends
	// -- would otherwise trip the limit at a fraction of the real file count.
	if _, seen := fl.seen[path]; seen {
		return nil
	}

	// Check file count limit to prevent resource exhaustion. Counted after
	// normalization, de-duplication and the empty-path skip, so the number
	// checked is the number of files that will actually be scanned.
	if len(fl.files) >= MaxFiles {
		return fmt.Errorf("%w: maximum %d files allowed", ErrTooManyFiles, MaxFiles)
	}

	if fl.seen == nil {
		fl.seen = make(map[string]struct{})
	}
	fl.seen[path] = struct{}{}
	fl.files = append(fl.files, path)
	return nil
}

// relativeToRoot turns an absolute path into a path relative to the repository
// root, with symlinks resolved on *both* sides so the comparison is between real
// filesystem locations rather than spellings (CWE-22: a symlink pointing out of
// the repository still resolves out of it and is still rejected).
//
// Resolving only one side -- which is what this used to do, taking the relative
// path from the unresolved root after checking containment against the resolved
// one -- rejects a legitimate selection whenever the repository root is itself
// reached through a symlink. /tmp and /var are symlinks to /private/... on macOS,
// so an absolute path under any temporary directory hit this.
func (fl *FileList) relativeToRoot(path string) (string, error) {
	rel, err := filepath.Rel(resolveExisting(fl.repoRoot), resolveExisting(path))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("absolute path %q is outside repository root %q", path, fl.repoRoot)
	}
	return rel, nil
}

// resolveExisting resolves symlinks in path. A path that does not exist yet is
// still resolved as far as it can be: EvalSymlinks fails on a missing leaf, so
// the deepest existing ancestor is resolved and the remainder re-appended. A
// file that is about to be created therefore resolves through its symlinked
// parents the same way an existing one does.
func resolveExisting(path string) string {
	cleaned := filepath.Clean(path)
	remainder := ""
	for current := cleaned; ; {
		if resolved, err := filepath.EvalSymlinks(current); err == nil {
			return filepath.Join(resolved, remainder)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return cleaned // nothing along this path exists
		}
		remainder = filepath.Join(filepath.Base(current), remainder)
		current = parent
	}
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
