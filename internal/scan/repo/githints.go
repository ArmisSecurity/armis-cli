package repo

import (
	"path/filepath"
	"strings"
)

// GitHints carries the optional git-derived metadata sent alongside a repo
// upload so the server can resolve an incremental-scan baseline. Every field is
// best-effort: an empty string means "not detected, omit from the payload".
//
// See PPSC-1215. The field semantics form a strict contract with the server:
//   - RepoName  — canonical repo identity (SCM provider's owner/repo name).
//   - GitSHA    — commit SHA of the uploaded tree; the server's write key for a
//     new baseline index entry. Only populated when the working tree is clean,
//     so the uploaded archive is a faithful snapshot of that commit.
//   - OriginSHA — most recent ancestor known to exist on origin; a read-only
//     fallback key, never used by the server to write a baseline entry.
type GitHints struct {
	RepoName  string
	GitSHA    string
	OriginSHA string
}

// DetectGitHints inspects the git checkout at scanPath and returns the hints
// derivable from it. Detection is entirely best-effort: any failure (not a git
// repo, git not installed, no origin remote, shallow clone with no merge-base,
// dirty working tree) results in the corresponding field being left empty
// rather than an error. It never fails the upload.
//
// Hints are only produced when scanPath IS the git repository root. A subdirectory
// scan yields no hints, because repo_name and the baseline it keys are whole-repo
// concepts — a subtree upload is not a faithful snapshot of the repository at a
// commit, so a baseline diff against it would be meaningless.
func DetectGitHints(scanPath string) GitHints {
	var hints GitHints

	absPath, err := filepath.Abs(scanPath)
	if err != nil {
		return hints
	}
	if resolved, err := filepath.EvalSymlinks(absPath); err == nil {
		absPath = resolved
	}

	// Only emit hints when the scan target is the repository root. gitRepoRoot
	// already resolves symlinks, so both sides are canonical for comparison.
	repoRoot, err := gitRepoRoot(absPath)
	if err != nil || repoRoot != absPath {
		return hints
	}

	// repo_name — parsed from the origin remote URL. Omitted if there's no
	// origin remote or the URL can't be normalized to owner/repo.
	if remoteURL, err := runGit(repoRoot, "remote", "get-url", "origin"); err == nil {
		hints.RepoName = normalizeRepoName(strings.TrimSpace(remoteURL))
	}

	// git_sha — HEAD commit, but only when the working tree is clean. A dirty
	// tree means the uploaded archive would not match the commit, so the server
	// must not key a baseline entry to it.
	if isCleanWorkingTree(repoRoot) {
		if sha, err := runGit(repoRoot, "rev-parse", "HEAD"); err == nil {
			hints.GitSHA = strings.TrimSpace(sha)
		}
	}

	// origin_sha — merge-base of HEAD with the default branch on origin. Omitted
	// if the branch can't be determined or there's no common ancestor (e.g. an
	// unrelated-history shallow clone).
	if branch := detectDefaultBranch(repoRoot); branch != "" {
		if base, err := runGit(repoRoot, "merge-base", "HEAD", "origin/"+branch); err == nil {
			hints.OriginSHA = strings.TrimSpace(base)
		}
	}

	return hints
}

// isCleanWorkingTree reports whether the working tree at repoRoot has no staged,
// unstaged, or untracked changes. Files ignored by .gitignore do not count as
// untracked, so gitignored build artifacts do not mark the tree dirty.
func isCleanWorkingTree(repoRoot string) bool {
	out, err := runGit(repoRoot, "status", "--porcelain")
	if err != nil {
		return false
	}
	return strings.TrimSpace(out) == ""
}

// detectDefaultBranch resolves the origin default branch name used to compute
// origin_sha. Resolution order:
//  1. origin/HEAD symbolic ref (present when the clone recorded it)
//  2. probe origin/main, then origin/master
//
// Returns the bare branch name (no "origin/" prefix), or "" if none resolves.
func detectDefaultBranch(repoRoot string) string {
	// git symbolic-ref refs/remotes/origin/HEAD -> "refs/remotes/origin/<branch>"
	if out, err := runGit(repoRoot, "symbolic-ref", "refs/remotes/origin/HEAD"); err == nil {
		ref := strings.TrimSpace(out)
		const prefix = "refs/remotes/origin/"
		if strings.HasPrefix(ref, prefix) {
			if branch := strings.TrimPrefix(ref, prefix); branch != "" {
				return branch
			}
		}
	}

	// Fall back to the conventional default branch names. --verify + a quiet
	// failure keeps this a local, no-network probe.
	for _, branch := range []string{"main", "master"} {
		if _, err := runGit(repoRoot, "rev-parse", "--verify", "--quiet", "refs/remotes/origin/"+branch); err == nil {
			return branch
		}
	}

	return ""
}

// normalizeRepoName reduces a git remote URL to its canonical "owner/repo"
// identity, matching the SCM provider naming the server keys baselines on.
// Returns "" if the URL can't be reduced to a plausible owner/repo pair.
//
// Handles the common remote URL shapes:
//   - git@github.com:org/repo.git          (scp-like syntax)
//   - https://github.com/org/repo.git       (https)
//   - https://user@host/org/repo.git        (https with userinfo)
//   - ssh://git@host:22/org/repo.git         (ssh with port)
func normalizeRepoName(rawURL string) string {
	s := strings.TrimSpace(rawURL)
	if s == "" {
		return ""
	}

	// Normalize backslashes to forward slashes. Real git remote URLs never use
	// backslashes, but a local-filesystem clone on Windows yields an origin URL
	// like `C:\path\to\repo`; without this the path segments can't be split and
	// detection silently drops repo_name. Harmless for genuine URLs.
	s = strings.ReplaceAll(s, "\\", "/")

	// Strip a scheme prefix ("https://", "ssh://", "git://", ...).
	if i := strings.Index(s, "://"); i != -1 {
		s = s[i+3:]
	}

	// Strip userinfo ("git@", "user@").
	if i := strings.LastIndex(s, "@"); i != -1 {
		s = s[i+1:]
	}

	// Split off the host from the path. scp-like syntax uses "host:org/repo";
	// URL syntax uses "host/org/repo" (possibly "host:port/org/repo").
	if i := strings.IndexAny(s, ":/"); i != -1 {
		s = s[i+1:]
	} else {
		// No separator at all — can't be a repo path.
		return ""
	}

	// Drop a leading port that survived scp/URL splitting (e.g. "22/org/repo").
	s = strings.TrimPrefix(s, "/")

	// Trim a trailing ".git" and any surrounding slashes.
	s = strings.Trim(s, "/")
	s = strings.TrimSuffix(s, ".git")
	s = strings.Trim(s, "/")
	if s == "" {
		return ""
	}

	// Reduce to the last two path segments -> owner/repo. This drops any port
	// segment left over from URL syntax and collapses deeper paths to the
	// trailing owner/repo, matching GitHub-style full_name.
	parts := strings.Split(s, "/")
	if len(parts) < 2 {
		return ""
	}
	owner := parts[len(parts)-2]
	repoName := parts[len(parts)-1]
	if owner == "" || repoName == "" {
		return ""
	}
	return owner + "/" + repoName
}
