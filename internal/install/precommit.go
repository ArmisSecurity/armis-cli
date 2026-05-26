package install

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	preCommitMarkerStart = "# --- armis-appsec pre-commit hook (start) ---"
	preCommitMarkerEnd   = "# --- armis-appsec pre-commit hook (end) ---"
)

// PreCommitOpts configures the git pre-commit hook behavior.
type PreCommitOpts struct {
	FailOpen bool // warn but don't block (exit 0 always)
}

// InstallPreCommit installs the Armis security scanning hook into the git repo's
// pre-commit hook. If a pre-commit hook already exists, the Armis section is
// appended between marker comments. If the plugin ships a git-hooks/pre-commit
// script, that is used; otherwise a fallback that calls armis-cli directly is written.
func InstallPreCommit(repoRoot, pluginDir string, opts PreCommitOpts) error {
	if !filepath.IsAbs(repoRoot) {
		return fmt.Errorf("repo root must be an absolute path: %s", repoRoot)
	}
	// armis:ignore cwe:73 reason:repoRoot validated absolute by guard above; ".git" is hardcoded literal
	gitEntry := filepath.Join(repoRoot, ".git")
	// armis:ignore cwe:73 reason:repoRoot validated as absolute path above; .git is a hardcoded segment
	if _, err := os.Stat(gitEntry); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("not a git repository (no .git): %s", repoRoot)
		}
		return fmt.Errorf("checking .git: %w", err)
	}

	hookDir, err := resolveHooksDir(repoRoot)
	if err != nil {
		return err
	}
	if _, err := os.Stat(hookDir); os.IsNotExist(err) {
		// armis:ignore cwe:73 reason:hookDir resolved from git rev-parse or validated repoRoot/.git
		if err := os.MkdirAll(hookDir, 0o750); err != nil {
			return fmt.Errorf("creating hooks directory: %w", err)
		}
	}

	hookPath := filepath.Join(hookDir, "pre-commit")

	// Build the hook script content
	armisSection := buildPreCommitSection(pluginDir, opts)

	// armis:ignore cwe:73 reason:hookPath derived from git hooks dir + hardcoded "pre-commit" filename
	existing, err := os.ReadFile(filepath.Clean(hookPath)) //nolint:gosec // hookPath from git repo + hardcoded segment
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("reading existing pre-commit hook: %w", err)
	}

	var content string
	if len(existing) == 0 {
		content = "#!/bin/sh\n" + armisSection
	} else {
		existingStr := string(existing)
		if strings.Contains(existingStr, preCommitMarkerStart) {
			return nil // already installed
		}
		content = existingStr + "\n" + armisSection
	}

	if err := os.WriteFile(filepath.Clean(hookPath), []byte(content), 0o755); err != nil { //nolint:gosec // hookPath from git repo
		return fmt.Errorf("writing pre-commit hook: %w", err)
	}
	return nil
}

// RemovePreCommit removes the Armis section from the git pre-commit hook.
// If the Armis section is the only content, the hook file is removed entirely.
func RemovePreCommit(repoRoot string) error {
	hookDir, err := resolveHooksDir(repoRoot)
	if err != nil {
		if _, statErr := os.Stat(filepath.Join(repoRoot, ".git")); os.IsNotExist(statErr) {
			return nil // not a git repo — nothing to remove
		}
		return fmt.Errorf("resolving hooks directory: %w", err)
	}
	hookPath := filepath.Join(hookDir, "pre-commit")

	// armis:ignore cwe:73 reason:hookPath derived from git hooks dir + hardcoded "pre-commit" filename
	data, err := os.ReadFile(filepath.Clean(hookPath)) //nolint:gosec // hookPath from git repo
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading pre-commit hook: %w", err)
	}

	content := string(data)
	startIdx := strings.Index(content, preCommitMarkerStart)
	if startIdx == -1 {
		return nil // no armis section found
	}
	endIdx := strings.Index(content[startIdx:], preCommitMarkerEnd)
	if endIdx == -1 {
		return nil // no armis section found
	}
	endIdx += startIdx

	// Remove the armis section including trailing newline
	endIdx += len(preCommitMarkerEnd)
	if endIdx < len(content) && content[endIdx] == '\n' {
		endIdx++
	}
	// Remove leading newline before start marker if present
	if startIdx > 0 && content[startIdx-1] == '\n' {
		startIdx--
	}

	remaining := content[:startIdx] + content[endIdx:]
	remaining = strings.TrimRight(remaining, "\n")

	// If only the shebang remains, remove the file
	if remaining == "" || remaining == "#!/bin/sh" || remaining == "#!/bin/bash" {
		return os.Remove(filepath.Clean(hookPath))
	}

	// armis:ignore cwe:73 reason:hookPath derived from git hooks dir + hardcoded "pre-commit" filename
	return os.WriteFile(filepath.Clean(hookPath), []byte(remaining+"\n"), 0o755) //nolint:gosec // hookPath from git repo
}

// IsPreCommitInstalled checks whether the Armis pre-commit hook is installed.
func IsPreCommitInstalled(repoRoot string) bool {
	hookDir, err := resolveHooksDir(repoRoot)
	if err != nil {
		return false
	}
	hookPath := filepath.Join(hookDir, "pre-commit")
	// armis:ignore cwe:73 reason:hookPath derived from git hooks dir + hardcoded "pre-commit" filename
	data, err := os.ReadFile(filepath.Clean(hookPath)) //nolint:gosec // hookPath from git repo
	if err != nil {
		return false
	}
	return strings.Contains(string(data), preCommitMarkerStart)
}

// resolveHooksDir returns the git hooks directory for a repo, supporting
// both regular repos (.git directory) and worktrees/submodules (.git file).
func resolveHooksDir(repoRoot string) (string, error) {
	// armis:ignore cwe:78 reason:hardcoded command "git" with hardcoded args, no user input
	// armis:ignore cwe:73 reason:repoRoot validated as absolute path by caller
	cmd := exec.Command("git", "rev-parse", "--git-path", "hooks") //nolint:gosec // hardcoded command
	cmd.Dir = repoRoot
	if out, err := cmd.Output(); err == nil {
		hookDir := strings.TrimSpace(string(out))
		if !filepath.IsAbs(hookDir) {
			hookDir = filepath.Join(repoRoot, hookDir)
		}
		return hookDir, nil
	}

	// Fallback: check if .git is a directory (standard repo) or file (worktree)
	gitEntry := filepath.Join(repoRoot, ".git")
	info, err := os.Stat(gitEntry)
	if err != nil {
		return "", fmt.Errorf("resolving hooks directory: %w", err)
	}
	if info.IsDir() {
		return filepath.Join(gitEntry, "hooks"), nil
	}
	// .git file — parse gitdir pointer
	// armis:ignore cwe:73 reason:gitEntry is repoRoot (validated absolute) + hardcoded ".git"
	data, err := os.ReadFile(gitEntry) //nolint:gosec // path from validated repoRoot
	if err != nil {
		return "", fmt.Errorf("reading .git file: %w", err)
	}
	content := strings.TrimSpace(string(data))
	if !strings.HasPrefix(content, "gitdir: ") {
		return "", fmt.Errorf("unexpected .git file format in %s", repoRoot)
	}
	gitDir := strings.TrimPrefix(content, "gitdir: ")
	if !filepath.IsAbs(gitDir) {
		gitDir = filepath.Join(repoRoot, gitDir)
	}
	return filepath.Join(gitDir, "hooks"), nil
}

// DetectGitRoot returns the git repository root for the current directory,
// or empty string if not inside a git repo.
func DetectGitRoot() string {
	// armis:ignore cwe:78 reason:hardcoded command "git" with hardcoded args, no user input
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output() //nolint:gosec // hardcoded command
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func buildPreCommitSection(pluginDir string, opts PreCommitOpts) string {
	var sb strings.Builder
	sb.WriteString(preCommitMarkerStart)
	sb.WriteString("\n")

	// Check if the plugin ships a pre-commit script
	pluginPreCommit := filepath.Join(pluginDir, "git-hooks", "pre-commit")
	if _, err := os.Stat(pluginPreCommit); err == nil {
		// Use the plugin's pre-commit script (handles .scan-pass verification)
		if opts.FailOpen {
			sb.WriteString("# Armis AppSec: security scan verification (fail-open mode)\n")
			// armis:ignore cwe:78 reason:pluginPreCommit is pluginDir+hardcoded segments; posixQuote escapes shell metacharacters
			sb.WriteString(fmt.Sprintf("if ! %s; then\n", posixQuote(pluginPreCommit)))
			sb.WriteString("  echo \"⚠️  Armis: scan verification failed (continuing in fail-open mode)\" >&2\n")
			sb.WriteString("fi\n")
		} else {
			sb.WriteString("# Armis AppSec: security scan verification\n")
			// armis:ignore cwe:78 reason:pluginPreCommit is pluginDir+hardcoded segments; posixQuote escapes shell metacharacters
			sb.WriteString(fmt.Sprintf("exec %s\n", posixQuote(pluginPreCommit)))
		}
	} else {
		// Fallback: call armis-cli directly
		failOn := "HIGH"
		cmd := fmt.Sprintf("armis-cli scan repo . --changed=staged --no-progress --fail-on %s", failOn)
		if opts.FailOpen {
			sb.WriteString("# Armis AppSec: security scan (fail-open mode)\n")
			sb.WriteString(fmt.Sprintf("if ! %s 2>/dev/null; then\n", cmd))
			sb.WriteString("  echo \"⚠️  Armis: security findings detected (continuing in fail-open mode)\" >&2\n")
			sb.WriteString("fi\n")
		} else {
			sb.WriteString("# Armis AppSec: security scan\n")
			sb.WriteString(fmt.Sprintf("exec %s\n", cmd))
		}
	}

	sb.WriteString(preCommitMarkerEnd)
	sb.WriteString("\n")
	return sb.String()
}
