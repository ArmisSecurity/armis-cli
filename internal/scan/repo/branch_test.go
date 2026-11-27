package repo

import (
	"strings"
	"testing"
)

// clearCIBranchEnv unsets every CI variable that names a branch, so a test
// sees only the branch it sets, wherever it runs (CI sets its own).
func clearCIBranchEnv(t *testing.T) {
	t.Helper()
	for _, name := range ciBranchEnvVars() {
		t.Setenv(name, "")
	}
}

func TestValidBranch(t *testing.T) {
	valid := []string{
		"main", "feature/login", "release-1.2", "a.b", "user/x_y", "v1.2.3", "a@b",
		strings.Repeat("b", maxBranchLength),
	}
	for _, name := range valid {
		if !validBranch(name) {
			t.Errorf("validBranch(%q) = false, want true", name)
		}
	}
	invalid := []string{
		"", "HEAD", "@", "-x", "a..b", "a/", "/a", "a//b", ".a", "a/.b", "a.lock",
		"a/b.lock/c", "a.", "a@{1}", "a b", "a~1", "a^2", "a:b", "a?", "a*", "a[0",
		`a\b`, "a\tb", "a\nb", "a\x7fb", "café", "a\u200bb",
		strings.Repeat("b", maxBranchLength+1),
	}
	for _, name := range invalid {
		if validBranch(name) {
			t.Errorf("validBranch(%q) = true, want false", name)
		}
	}
}

// ValidateBranch holds --branch to validBranch's rule, and says why.
func TestValidateBranch(t *testing.T) {
	if err := ValidateBranch("release/2026.11"); err != nil {
		t.Errorf("a valid branch: %v", err)
	}
	for _, name := range []string{"", "feature branch", "-main", "a..b", "café"} {
		if err := ValidateBranch(name); err == nil || !strings.Contains(err.Error(), "not a branch name git accepts") {
			t.Errorf("ValidateBranch(%q) = %v, want the rule", name, err)
		}
	}
}

func TestCIBranch(t *testing.T) {
	for _, tt := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{"none", nil, ""},
		{"a GitHub pull request's source branch", map[string]string{
			"GITHUB_HEAD_REF": "feature/login", "GITHUB_REF_TYPE": "branch", "GITHUB_REF_NAME": "42/merge",
		}, "feature/login"},
		{"a GitHub push's branch", map[string]string{
			"GITHUB_HEAD_REF": "", "GITHUB_REF_TYPE": "branch", "GITHUB_REF_NAME": "main",
		}, "main"},
		{"a GitHub tag build names no branch", map[string]string{
			"GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": "v1.2.3",
		}, ""},
		{"GitHub's own come first", map[string]string{
			"GITHUB_REF_TYPE": "branch", "GITHUB_REF_NAME": "main", "BRANCH_NAME": "other",
		}, "main"},
		{"a GitLab merge request before its branch", map[string]string{
			"CI_MERGE_REQUEST_SOURCE_BRANCH_NAME": "feature/x", "CI_COMMIT_BRANCH": "main",
		}, "feature/x"},
		{"an Azure pull request's source ref", map[string]string{
			"SYSTEM_PULLREQUEST_SOURCEBRANCH": "refs/heads/feature/y", "BUILD_SOURCEBRANCH": "refs/pull/7/merge",
		}, "feature/y"},
		{"an Azure branch ref", map[string]string{"BUILD_SOURCEBRANCH": "refs/heads/main"}, "main"},
		{"an Azure pull request ref names no branch", map[string]string{"BUILD_SOURCEBRANCH": "refs/pull/7/merge"}, ""},
		{"a tag ref names no branch", map[string]string{"CODEBUILD_WEBHOOK_HEAD_REF": "refs/tags/v1"}, ""},
		{"CircleCI", map[string]string{"CIRCLE_BRANCH": "develop"}, "develop"},
		{"a Jenkins remote branch", map[string]string{"GIT_BRANCH": "origin/feature/z"}, "feature/z"},
		{"a Jenkins multibranch name before the remote one", map[string]string{
			"BRANCH_NAME": "release/2", "GIT_BRANCH": "origin/main",
		}, "release/2"},
		{"a Jenkins multibranch branch build", map[string]string{
			"BRANCH_NAME": "main", "GIT_BRANCH": "main",
		}, "main"},
		{"a Jenkins pull request's source branch, not its PR-12", map[string]string{
			"CHANGE_ID": "12", "CHANGE_BRANCH": "feature/login", "CHANGE_TARGET": "main",
			"BRANCH_NAME": "PR-12", "GIT_BRANCH": "PR-12",
		}, "feature/login"},
		{"a Jenkins pull request without its source branch names none", map[string]string{
			"CHANGE_ID": "12", "BRANCH_NAME": "PR-12", "GIT_BRANCH": "PR-12",
		}, ""},
		{"a Jenkins tag build names no branch", map[string]string{
			"TAG_NAME": "v1.2", "BRANCH_NAME": "v1.2", "GIT_BRANCH": "v1.2",
		}, ""},
		{"another CI's branch before Jenkins'", map[string]string{
			"CIRCLE_BRANCH": "develop", "CHANGE_ID": "12", "CHANGE_BRANCH": "feature/login",
		}, "develop"},
		{"a name git refuses is skipped", map[string]string{
			"CIRCLE_BRANCH": "bad..name", "BUILDKITE_BRANCH": "good",
		}, "good"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			getenv := func(name string) string { return tt.env[name] }
			if got := ciBranch(getenv); got != tt.want {
				t.Errorf("ciBranch() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDetectBranch_TheCheckoutsBranch(t *testing.T) {
	clearCIBranchEnv(t)
	t.Setenv("CIRCLE_BRANCH", "from-ci")
	dir := setupGitRepo(t)
	if err := runGitCmd(t, dir, "checkout", "-b", "feature/login"); err != nil {
		t.Fatalf("checkout: %v", err)
	}

	if got := DetectBranch(dir); got != "feature/login" {
		t.Errorf("DetectBranch() = %q, want the checkout's own branch", got)
	}
}

func TestDetectBranch_ABranchNamedLikeATag(t *testing.T) {
	// A release branch with a tag of its name: git's short name for the branch
	// is then "heads/v1.2", a branch that doesn't exist.
	clearCIBranchEnv(t)
	dir := setupGitRepo(t)
	for _, args := range [][]string{{"checkout", "-b", "v1.2"}, {"tag", "v1.2"}} {
		if err := runGitCmd(t, dir, args...); err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
	}

	if got := DetectBranch(dir); got != "v1.2" {
		t.Errorf("DetectBranch() = %q, want the branch v1.2", got)
	}
}

func TestDetectBranch_ADetachedHeadFallsBackToCI(t *testing.T) {
	clearCIBranchEnv(t)
	dir := setupGitRepo(t)
	if err := runGitCmd(t, dir, "checkout", "--detach"); err != nil {
		t.Fatalf("checkout: %v", err)
	}

	if got := DetectBranch(dir); got != "" {
		t.Errorf("DetectBranch() = %q, want none outside CI", got)
	}
	t.Setenv("CI_COMMIT_BRANCH", "release/2.0")
	if got := DetectBranch(dir); got != "release/2.0" {
		t.Errorf("DetectBranch() = %q, want the CI branch", got)
	}
}

func TestDetectBranch_NotACheckout(t *testing.T) {
	clearCIBranchEnv(t)
	dir := t.TempDir()

	if got := DetectBranch(dir); got != "" {
		t.Errorf("DetectBranch() = %q, want none", got)
	}
	t.Setenv("BITBUCKET_BRANCH", "main")
	if got := DetectBranch(dir); got != "main" {
		t.Errorf("DetectBranch() = %q, want the CI branch", got)
	}
}
