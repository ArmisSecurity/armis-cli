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
	"unicode"
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
	// armis:ignore cwe:770 reason:git output bounded by repository size; repoRoot validated by caller
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
	filtered, err := filterToScanPath(repoRoot, absPath, changedPaths)
	if err != nil {
		return nil, err
	}

	if len(filtered) == 0 {
		return nil, ErrNoChangedFiles
	}

	// Use ParseFileList for security validation (path traversal checks, MaxFiles limit).
	//
	// Note: we intentionally do NOT fail closed if an individual changed path
	// later turns out to be unscannable (a symlink, a file that vanished, or a
	// directory). Those are legitimate, intentional skips — symlinks are a
	// security skip shared with full-directory scans, and untracked files
	// surfaced by `ls-files --others` (editor swapfiles, build artifacts) can
	// vanish between detection and archiving. The scan-scope bypass this
	// addresses was control-character filenames being silently dropped, and the
	// -z (NUL-delimited) output above closes that fully: such names now
	// round-trip verbatim and resolve on disk like any other file.
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

	// armis:ignore cwe:22 reason:repoRoot from git rev-parse --show-toplevel; filepath.Clean applied above
	return repoRoot, nil
}

// changedUncommitted returns files with uncommitted changes (staged + unstaged + untracked).
func changedUncommitted(repoRoot string) ([]string, error) {
	// Get staged and unstaged modified files.
	// --diff-filter=ACMRT excludes deleted files (D).
	// -z emits NUL-terminated, unquoted pathnames so filenames containing
	// newlines, tabs, or other control characters round-trip losslessly
	// (without -z, git C-quotes such paths and packs them onto one line each,
	// so newline splitting would silently drop them — a scan-scope bypass).
	diffOutput, err := runGit(repoRoot, "diff", "--name-only", "-z", "--diff-filter=ACMRT", "HEAD")
	if err != nil {
		// If HEAD doesn't exist (fresh repo with no commits), get staged files instead.
		// Check for specific git error messages indicating missing HEAD revision.
		if strings.Contains(err.Error(), "unknown revision") ||
			strings.Contains(err.Error(), "bad revision") {
			stagedOutput, stagedErr := runGit(repoRoot, "diff", "--name-only", "-z", "--diff-filter=ACMRT", "--cached")
			if stagedErr != nil {
				return nil, fmt.Errorf("failed to get uncommitted changes (no HEAD and staged diff failed): %w", stagedErr)
			}
			diffOutput = stagedOutput
		} else {
			return nil, fmt.Errorf("failed to get uncommitted changes: %w", err)
		}
	}

	// Get untracked files (respects .gitignore). -z for the same reason as above.
	untrackedOutput, err := runGit(repoRoot, "ls-files", "--others", "--exclude-standard", "-z")
	if err != nil {
		return nil, fmt.Errorf("failed to get untracked files: %w", err)
	}

	return combineAndDedupe(parseNulSeparated(diffOutput), parseNulSeparated(untrackedOutput)), nil
}

// changedStaged returns only staged files.
func changedStaged(repoRoot string) ([]string, error) {
	// Get staged files only. -z for NUL-terminated, unquoted pathnames.
	// --diff-filter=ACMRT excludes deleted files (D)
	output, err := runGit(repoRoot, "diff", "--name-only", "-z", "--diff-filter=ACMRT", "--cached")
	if err != nil {
		return nil, fmt.Errorf("failed to get staged changes: %w", err)
	}
	return parseNulSeparated(output), nil
}

// validateRef checks that a git ref does not contain characters that could
// cause unexpected behavior. While exec.Command prevents shell injection,
// this provides defense-in-depth consistent with image name validation.
func validateRef(ref string) error {
	if strings.HasPrefix(ref, "-") {
		return fmt.Errorf("%w: %q (cannot start with dash)", ErrRefNotFound, ref)
	}
	for _, r := range ref {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return fmt.Errorf("%w: %q (contains illegal whitespace/control characters)", ErrRefNotFound, ref)
		}
	}
	return nil
}

// changedSinceRef returns files changed between the given ref and HEAD.
func changedSinceRef(repoRoot, ref string) ([]string, error) {
	// Validate ref for safety (defense-in-depth: prevent argument injection,
	// control characters, and whitespace)
	if err := validateRef(ref); err != nil {
		return nil, err
	}
	// Use three-dot notation to compare ref...HEAD (changes since common ancestor)
	// --diff-filter=ACMRT excludes deleted files (D)
	// -z emits NUL-terminated, unquoted pathnames (see changedUncommitted).
	output, err := runGit(repoRoot, "diff", "--name-only", "-z", "--diff-filter=ACMRT", ref+"...HEAD")
	if err != nil {
		// Check if the ref doesn't exist
		if strings.Contains(err.Error(), "unknown revision") ||
			strings.Contains(err.Error(), "bad revision") ||
			strings.Contains(err.Error(), "not a valid") {
			return nil, fmt.Errorf("%w: %q", ErrRefNotFound, ref)
		}
		return nil, fmt.Errorf("failed to get changes since %q: %w", ref, err)
	}
	return parseNulSeparated(output), nil
}

// filterToScanPath filters changedPaths (relative to repoRoot) to only include
// files within scanPath, and converts them to be relative to scanPath.
func filterToScanPath(repoRoot, scanPath string, changedPaths []string) ([]string, error) {
	// If scanPath IS the repo root, no filtering needed
	if repoRoot == scanPath {
		return changedPaths, nil
	}

	prefix, err := filepath.Rel(repoRoot, scanPath)
	if err != nil {
		return nil, fmt.Errorf("cannot compute relative path from repo root %q to scan path %q: %w",
			repoRoot, scanPath, err)
	}
	// Normalize to forward slashes for comparison
	prefix = filepath.ToSlash(prefix)
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	// Resolve symlinks on scanPath so containment checks compare real paths (CWE-22).
	resolvedScanPath, err := filepath.EvalSymlinks(scanPath)
	if err != nil {
		resolvedScanPath = scanPath
	}

	// armis:ignore cwe:22 reason:this loop IS the path traversal prevention (Clean + HasPrefix + EvalSymlinks)
	var filtered []string
	for _, p := range changedPaths {
		// Normalize path components (e.g., "subdir/../secret" -> "../secret")
		// to prevent path traversal bypassing the prefix check (CWE-22).
		// filepath.Clean must be called before ToSlash as it operates on native separators.
		cleanP := filepath.Clean(p)
		slashP := filepath.ToSlash(cleanP)
		// armis:ignore cwe:22 reason:filepath.Clean + HasPrefix IS the traversal prevention (this code is the mitigation)
		if strings.HasPrefix(slashP, prefix) {
			rel := strings.TrimPrefix(slashP, prefix)
			if rel != "" {
				// Resolve symlinks to reject paths that escape scanPath (CWE-22).
				// Only reject when resolution succeeds and proves escape; if the file
				// doesn't exist on disk (common for deleted files), the string-based
				// prefix check above is sufficient since Clean already rejected "..".
				absCandidate := filepath.Join(repoRoot, p)
				if resolved, err := filepath.EvalSymlinks(absCandidate); err == nil {
					if !strings.HasPrefix(resolved, resolvedScanPath+string(filepath.Separator)) && resolved != resolvedScanPath {
						continue
					}
				}
				filtered = append(filtered, rel)
			}
		}
	}
	return filtered, nil
}

// runGit executes a git command in the given directory and returns stdout.
func runGit(dir string, args ...string) (string, error) {
	// #nosec G204 -- args constructed internally; user ref is validated and passed as separate argument
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	// Force English output for consistent error message parsing across locales
	cmd.Env = append(os.Environ(), "LC_ALL=C")

	// armis:ignore cwe:770 reason:git output bounded by repo size; used only for diff/log of controlled internal operations
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

// parseNulSeparated splits NUL-terminated git output (produced with the -z
// flag) into individual pathnames and removes empty entries.
//
// Unlike newline splitting, this is safe for pathnames containing ANY byte
// except NUL — including newlines, carriage returns, tabs, and other control
// characters. With -z git also disables path quoting, so each record is the
// raw, verbatim pathname; we must NOT trim CR or whitespace, as those bytes
// may be a legitimate part of the filename.
func parseNulSeparated(output string) []string {
	if output == "" {
		return nil
	}
	// -z terminates each record with a NUL, so the split yields a trailing
	// empty element after the final NUL; the empty-string check drops it.
	parts := strings.Split(output, "\x00")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// combineAndDedupe combines multiple pathname lists and removes duplicates,
// preserving first-seen order.
func combineAndDedupe(lists ...[]string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, list := range lists {
		for _, path := range list {
			if !seen[path] {
				seen[path] = true
				result = append(result, path)
			}
		}
	}
	return result
}
