// Package repo provides repository scanning functionality.
package repo

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ChangedMode represents the type of changed files detection.
type ChangedMode int

const (
	// ChangedModeUncommitted detects all uncommitted changes (staged + unstaged + untracked vs HEAD).
	ChangedModeUncommitted ChangedMode = iota
	// ChangedModeStaged detects only staged changes (index vs HEAD).
	ChangedModeStaged
	// ChangedModeRef detects changes between a specific git ref and HEAD.
	ChangedModeRef
)

// ChangedOptions configures how changed files are detected.
type ChangedOptions struct {
	Mode ChangedMode
	Ref  string // Only used when Mode == ChangedModeRef
}

// Sentinel errors for git change detection.
var (
	ErrNotGitRepo     = errors.New("not a git repository")
	ErrNoChangedFiles = errors.New("no changed files found")
	ErrRefNotFound    = errors.New("git reference not found")
	ErrGitNotFound    = errors.New("git command not found")
)

// GitChangedFiles returns a FileList of files changed in the git repository
// at scanPath according to the given options.
//
// The scanPath can be any subdirectory within a git repository. Only files
// within the scanPath subtree are included in the result.
//
// Returns an error if:
//   - scanPath is not within a git repository
//   - git command is not available
//   - the specified ref cannot be resolved (for ChangedModeRef)
//   - no changed files are found
func GitChangedFiles(scanPath string, opts ChangedOptions) (*FileList, error) {
	absPath, err := filepath.Abs(scanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path: %w", err)
	}

	// Resolve symlinks to ensure consistent path comparison
	// (On macOS, /tmp symlinks to /private/tmp which can cause path mismatches)
	absPath, err = filepath.EvalSymlinks(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path: %w", err)
	}

	// Find the git repository root
	repoRoot, err := gitRepoRoot(absPath)
	if err != nil {
		return nil, err
	}

	// Get changed files based on mode
	var changedPaths []string
	switch opts.Mode {
	case ChangedModeUncommitted:
		changedPaths, err = changedUncommitted(repoRoot)
	case ChangedModeStaged:
		changedPaths, err = changedStaged(repoRoot)
	case ChangedModeRef:
		changedPaths, err = changedSinceRef(repoRoot, opts.Ref)
	default:
		return nil, fmt.Errorf("unknown changed mode: %d", opts.Mode)
	}
	if err != nil {
		return nil, err
	}

	// Filter to only files within the scan path and convert to relative paths
	filtered := filterToScanPath(repoRoot, absPath, changedPaths)

	if len(filtered) == 0 {
		return nil, ErrNoChangedFiles
	}

	// Use ParseFileList for security validation (path traversal checks, MaxFiles limit)
	return ParseFileList(absPath, filtered)
}

// gitRepoRoot returns the git repository root for the given path.
func gitRepoRoot(path string) (string, error) {
	output, err := runGit(path, "rev-parse", "--show-toplevel")
	if err != nil {
		if errors.Is(err, ErrGitNotFound) {
			return "", err
		}
		return "", fmt.Errorf("%w: %s", ErrNotGitRepo, path)
	}
	// On Windows, git returns paths with forward slashes (e.g., C:/Users/...).
	// Convert to native path separators for consistent comparison with filepath.Abs results.
	repoRoot := filepath.FromSlash(strings.TrimSpace(output))
	repoRoot = filepath.Clean(repoRoot)

	// Resolve symlinks so that comparisons against other paths that have
	// been passed through filepath.EvalSymlinks (e.g., absPath) use the
	// same canonical form. If resolution fails, fall back to the cleaned path.
	if resolved, err := filepath.EvalSymlinks(repoRoot); err == nil {
		return resolved, nil
	}

	return repoRoot, nil
}

// changedUncommitted returns files with uncommitted changes (staged + unstaged + untracked).
func changedUncommitted(repoRoot string) ([]string, error) {
	// Get staged and unstaged modified files
	// --diff-filter=ACMRT excludes deleted files (D)
	diffOutput, err := runGit(repoRoot, "diff", "--name-only", "--diff-filter=ACMRT", "HEAD")
	if err != nil {
		// If HEAD doesn't exist (fresh repo with no commits), get staged files instead.
		// Check for specific git error messages indicating missing HEAD revision.
		if strings.Contains(err.Error(), "unknown revision") ||
			strings.Contains(err.Error(), "bad revision") {
			stagedOutput, stagedErr := runGit(repoRoot, "diff", "--name-only", "--diff-filter=ACMRT", "--cached")
			if stagedErr != nil {
				return nil, fmt.Errorf("failed to get uncommitted changes (no HEAD and staged diff failed): %w", stagedErr)
			}
			diffOutput = stagedOutput
		} else {
			return nil, fmt.Errorf("failed to get uncommitted changes: %w", err)
		}
	}

	// Get untracked files (respects .gitignore)
	untrackedOutput, err := runGit(repoRoot, "ls-files", "--others", "--exclude-standard")
	if err != nil {
		return nil, fmt.Errorf("failed to get untracked files: %w", err)
	}

	return combineAndDedupe(diffOutput, untrackedOutput), nil
}

// changedStaged returns only staged files.
func changedStaged(repoRoot string) ([]string, error) {
	// Get staged files only
	// --diff-filter=ACMRT excludes deleted files (D)
	output, err := runGit(repoRoot, "diff", "--name-only", "--diff-filter=ACMRT", "--cached")
	if err != nil {
		return nil, fmt.Errorf("failed to get staged changes: %w", err)
	}
	return parseLines(output), nil
}

// changedSinceRef returns files changed between the given ref and HEAD.
func changedSinceRef(repoRoot, ref string) ([]string, error) {
	// Validate ref doesn't look like a flag (prevent git argument injection)
	if strings.HasPrefix(ref, "-") {
		return nil, fmt.Errorf("%w: %q (cannot start with dash)", ErrRefNotFound, ref)
	}
	// Use three-dot notation to compare ref...HEAD (changes since common ancestor)
	// --diff-filter=ACMRT excludes deleted files (D)
	output, err := runGit(repoRoot, "diff", "--name-only", "--diff-filter=ACMRT", ref+"...HEAD")
	if err != nil {
		// Check if the ref doesn't exist
		if strings.Contains(err.Error(), "unknown revision") ||
			strings.Contains(err.Error(), "bad revision") ||
			strings.Contains(err.Error(), "not a valid") {
			return nil, fmt.Errorf("%w: %q", ErrRefNotFound, ref)
		}
		return nil, fmt.Errorf("failed to get changes since %q: %w", ref, err)
	}
	return parseLines(output), nil
}

// filterToScanPath filters changedPaths (relative to repoRoot) to only include
// files within scanPath, and converts them to be relative to scanPath.
func filterToScanPath(repoRoot, scanPath string, changedPaths []string) []string {
	// If scanPath IS the repo root, no filtering needed
	if repoRoot == scanPath {
		return changedPaths
	}

	prefix, err := filepath.Rel(repoRoot, scanPath)
	if err != nil {
		return nil
	}
	// Normalize to forward slashes for comparison
	prefix = filepath.ToSlash(prefix)
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	var filtered []string
	for _, p := range changedPaths {
		slashP := filepath.ToSlash(p)
		if strings.HasPrefix(slashP, prefix) {
			rel := strings.TrimPrefix(slashP, prefix)
			if rel != "" {
				filtered = append(filtered, rel)
			}
		}
	}
	return filtered
}

// runGit executes a git command in the given directory and returns stdout.
func runGit(dir string, args ...string) (string, error) {
	// #nosec G204 -- args constructed internally; user ref is validated and passed as separate argument
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	// Force English output for consistent error message parsing across locales
	cmd.Env = append(os.Environ(), "LC_ALL=C")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// Check if git is not installed
		if errors.Is(err, exec.ErrNotFound) {
			return "", fmt.Errorf("%w: git command not found (required for --changed)", ErrGitNotFound)
		}
		// Include stderr in error for debugging
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// parseLines splits output by newlines and removes empty entries.
// It only trims trailing newline/CR characters, preserving any spaces
// in filenames (git can track files with leading/trailing spaces).
func parseLines(output string) []string {
	// Only trim trailing newlines from the output, not all whitespace
	// (a filename could legitimately start with a space)
	output = strings.TrimRight(output, "\n\r")
	if output == "" {
		return nil
	}
	lines := strings.Split(output, "\n")
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		// Only trim trailing CR (for Windows CRLF compatibility), not spaces
		line = strings.TrimSuffix(line, "\r")
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

// combineAndDedupe combines two newline-separated outputs and removes duplicates.
func combineAndDedupe(outputs ...string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, output := range outputs {
		for _, line := range parseLines(output) {
			if !seen[line] {
				seen[line] = true
				result = append(result, line)
			}
		}
	}
	return result
}
