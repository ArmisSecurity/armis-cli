package repo

import (
	"os"
	"strings"
)

// maxBranchLength is the longest branch name Armis files a run under.
const maxBranchLength = 255

// ciBranchVars are the CI variables that name the branch a pipeline builds,
// most specific first: a pull or merge request's source branch before the
// branch a build ran on. A value may be a full ref ("refs/heads/main").
// GitHub Actions' own come first, and Jenkins' last, in ciBranch.
var ciBranchVars = []string{
	"CI_MERGE_REQUEST_SOURCE_BRANCH_NAME",    // GitLab, merge request pipelines
	"CI_COMMIT_BRANCH",                       // GitLab, branch pipelines
	"SYSTEM_PULLREQUEST_SOURCEBRANCH",        // Azure Pipelines, pull requests
	"BUILD_SOURCEBRANCH",                     // Azure Pipelines
	"BITBUCKET_BRANCH",                       // Bitbucket Pipelines
	"CIRCLE_BRANCH",                          // CircleCI
	"BUILDKITE_BRANCH",                       // Buildkite
	"TRAVIS_PULL_REQUEST_BRANCH",             // Travis CI, pull requests
	"TRAVIS_BRANCH",                          // Travis CI
	"DRONE_SOURCE_BRANCH",                    // Drone, pull requests
	"DRONE_BRANCH",                           // Drone
	"CODEBUILD_WEBHOOK_HEAD_REF",             // AWS CodeBuild
	"SEMAPHORE_GIT_PR_BRANCH",                // Semaphore, pull requests
	"SEMAPHORE_GIT_BRANCH",                   // Semaphore
	"APPVEYOR_PULL_REQUEST_HEAD_REPO_BRANCH", // AppVeyor, pull requests
	"APPVEYOR_REPO_BRANCH",                   // AppVeyor
	"BITRISE_GIT_BRANCH",                     // Bitrise
}

// The Jenkins variables jenkinsBranch reads.
const (
	// jenkinsChangeBranch names a change request's source branch, in a
	// multibranch build of a pull request.
	jenkinsChangeBranch = "CHANGE_BRANCH"
	// jenkinsChangeID is set in a multibranch build of a change request.
	jenkinsChangeID = "CHANGE_ID"
	// jenkinsTagName is set in a multibranch build of a tag.
	jenkinsTagName = "TAG_NAME"
	// jenkinsBranchName names what a multibranch build builds: a branch, a
	// change request ("PR-12") or a tag.
	jenkinsBranchName = "BRANCH_NAME"
	// jenkinsGitBranch names the remote branch a Jenkins git checkout built,
	// such as "origin/main", or in a multibranch build its BRANCH_NAME.
	jenkinsGitBranch = "GIT_BRANCH"
)

// ciBranchEnvVars returns every environment variable ciBranch consults, so
// tests can clear them all to simulate a run outside CI.
func ciBranchEnvVars() []string {
	vars := []string{
		"GITHUB_HEAD_REF", "GITHUB_REF_TYPE", "GITHUB_REF_NAME",
		jenkinsChangeBranch, jenkinsChangeID, jenkinsTagName, jenkinsBranchName, jenkinsGitBranch,
	}
	return append(vars, ciBranchVars...)
}

// DetectBranch returns the branch of the tree at scanPath, which a published
// scan's run is filed under, or "" when none is known. The checkout's own
// branch comes first; a detached HEAD, as CI checkouts often are, falls back
// to the CI variables that name the branch the pipeline builds. A name git
// would refuse as a branch is never returned, so the server never refuses it.
func DetectBranch(scanPath string) string {
	// The full ref, not --short: that prints "heads/main" for refs/heads/main
	// when a tag named main exists too.
	if out, err := runGit(scanPath, "symbolic-ref", "--quiet", "HEAD"); err == nil {
		if branch, ok := strings.CutPrefix(strings.TrimSpace(out), "refs/heads/"); ok && validBranch(branch) {
			return branch
		}
	}
	return ciBranch(os.Getenv)
}

// ciBranch is the first branch a CI variable names. GitHub Actions names a
// pull request's source branch in GITHUB_HEAD_REF, and a push's branch in
// GITHUB_REF_NAME, which names a tag on a tag build.
func ciBranch(getenv func(string) string) string {
	if branch := branchOfRef(getenv("GITHUB_HEAD_REF")); branch != "" {
		return branch
	}
	if getenv("GITHUB_REF_TYPE") == "branch" {
		if branch := branchOfRef(getenv("GITHUB_REF_NAME")); branch != "" {
			return branch
		}
	}
	for _, name := range ciBranchVars {
		if branch := branchOfRef(getenv(name)); branch != "" {
			return branch
		}
	}
	return jenkinsBranch(getenv)
}

// jenkinsBranch is the branch a Jenkins build names. A multibranch build of a
// pull request names its source branch in CHANGE_BRANCH, while its
// BRANCH_NAME and GIT_BRANCH name the change itself ("PR-12"), as a tag
// build's name the tag: those two are read only for a build of a branch.
func jenkinsBranch(getenv func(string) string) string {
	if branch := branchOfRef(getenv(jenkinsChangeBranch)); branch != "" {
		return branch
	}
	if getenv(jenkinsChangeID) != "" || getenv(jenkinsTagName) != "" {
		return ""
	}
	if branch := branchOfRef(getenv(jenkinsBranchName)); branch != "" {
		return branch
	}
	return branchOfRef(strings.TrimPrefix(getenv(jenkinsGitBranch), "origin/"))
}

// branchOfRef is the branch a CI variable's value names: a branch ref's name,
// or the value itself; "" for a tag or pull request ref, or a name git would
// refuse.
func branchOfRef(value string) string {
	ref := strings.TrimSpace(value)
	switch {
	case strings.HasPrefix(ref, "refs/heads/"):
		ref = strings.TrimPrefix(ref, "refs/heads/")
	case strings.HasPrefix(ref, "refs/"):
		return ""
	}
	if !validBranch(ref) {
		return ""
	}
	return ref
}

// validBranch reports whether name is a branch name `git check-ref-format
// --branch` accepts, of at most maxBranchLength printable ASCII characters:
// the rule the server holds a run's branch to, with nothing it might refuse.
func validBranch(name string) bool {
	if name == "" || len(name) > maxBranchLength {
		return false
	}
	if name == "@" || name == "HEAD" || strings.HasPrefix(name, "-") {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c <= ' ' || c >= 0x7f || strings.IndexByte("~^:?*[\\", c) >= 0 {
			return false
		}
	}
	if strings.Contains(name, "..") || strings.Contains(name, "@{") || strings.HasSuffix(name, ".") {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return false
		}
	}
	return true
}
