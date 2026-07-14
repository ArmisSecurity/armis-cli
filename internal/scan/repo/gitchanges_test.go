package repo

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// setupGitRepo creates a temporary git repository with an initial commit.
// Returns the repo path; cleanup is handled by t.TempDir().
func setupGitRepo(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()

	// Initialize git repo
	if err := runGitCmd(t, tmpDir, "init"); err != nil {
		t.Fatalf("Failed to init git repo: %v", err)
	}

	// Configure git user (required for commits)
	if err := runGitCmd(t, tmpDir, "config", "user.email", "test@example.com"); err != nil {
		t.Fatalf("Failed to configure git: %v", err)
	}
	if err := runGitCmd(t, tmpDir, "config", "user.name", "Test User"); err != nil {
		t.Fatalf("Failed to configure git: %v", err)
	}

	// Create initial file and commit
	if err := os.WriteFile(filepath.Join(tmpDir, "initial.txt"), []byte("initial content"), 0600); err != nil {
		t.Fatalf("Failed to create initial file: %v", err)
	}
	if err := runGitCmd(t, tmpDir, "add", "initial.txt"); err != nil {
		t.Fatalf("Failed to stage initial file: %v", err)
	}
	if err := runGitCmd(t, tmpDir, "commit", "-m", "Initial commit"); err != nil {
		t.Fatalf("Failed to create initial commit: %v", err)
	}

	return tmpDir
}

// runGitCmd is a helper to run git commands in tests.
// Output is captured and only logged on failure to keep CI output clean.
func runGitCmd(t *testing.T, dir string, args ...string) error {
	t.Helper()
	// #nosec G204 -- test helper with controlled args
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		t.Logf("git %s failed: %v\nstdout: %s\nstderr: %s",
			strings.Join(args, " "), err, stdout.String(), stderr.String())
	}
	return err
}

func TestGitChangedFiles_Uncommitted(t *testing.T) {
	// Skip if git is not available
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	repoDir := setupGitRepo(t)

	// Create a modified file (unstaged)
	modifiedFile := filepath.Join(repoDir, "initial.txt")
	if err := os.WriteFile(modifiedFile, []byte("modified content"), 0600); err != nil {
		t.Fatalf("Failed to modify file: %v", err)
	}

	// Create a new untracked file
	untrackedFile := filepath.Join(repoDir, "untracked.txt")
	if err := os.WriteFile(untrackedFile, []byte("untracked content"), 0600); err != nil {
		t.Fatalf("Failed to create untracked file: %v", err)
	}

	// Create a staged file
	stagedFile := filepath.Join(repoDir, "staged.txt")
	if err := os.WriteFile(stagedFile, []byte("staged content"), 0600); err != nil {
		t.Fatalf("Failed to create staged file: %v", err)
	}
	if err := runGitCmd(t, repoDir, "add", "staged.txt"); err != nil {
		t.Fatalf("Failed to stage file: %v", err)
	}

	// Test uncommitted mode
	fl, err := GitChangedFiles(repoDir, ChangedOptions{Mode: ChangedModeUncommitted})
	if err != nil {
		t.Fatalf("GitChangedFiles failed: %v", err)
	}

	files := fl.Files()
	if len(files) != 3 {
		t.Errorf("expected 3 changed files (modified, untracked, staged), got %d: %v", len(files), files)
	}

	// Verify all expected files are present
	fileSet := make(map[string]bool)
	for _, f := range files {
		fileSet[f] = true
	}
	for _, expected := range []string{"initial.txt", "untracked.txt", "staged.txt"} {
		if !fileSet[expected] {
			t.Errorf("expected file %q not found in results: %v", expected, files)
		}
	}
}

func TestGitChangedFiles_Staged(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	repoDir := setupGitRepo(t)

	// Create a staged file
	stagedFile := filepath.Join(repoDir, "staged.txt")
	if err := os.WriteFile(stagedFile, []byte("staged content"), 0600); err != nil {
		t.Fatalf("Failed to create staged file: %v", err)
	}
	if err := runGitCmd(t, repoDir, "add", "staged.txt"); err != nil {
		t.Fatalf("Failed to stage file: %v", err)
	}

	// Create an unstaged file (should NOT be included)
	unstagedFile := filepath.Join(repoDir, "unstaged.txt")
	if err := os.WriteFile(unstagedFile, []byte("unstaged content"), 0600); err != nil {
		t.Fatalf("Failed to create unstaged file: %v", err)
	}

	// Test staged mode
	fl, err := GitChangedFiles(repoDir, ChangedOptions{Mode: ChangedModeStaged})
	if err != nil {
		t.Fatalf("GitChangedFiles failed: %v", err)
	}

	files := fl.Files()
	if len(files) != 1 {
		t.Errorf("expected 1 staged file, got %d: %v", len(files), files)
	}
	if len(files) > 0 && files[0] != "staged.txt" {
		t.Errorf("expected staged.txt, got %s", files[0])
	}
}

func TestGitChangedFiles_Ref(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	repoDir := setupGitRepo(t)

	// Create a branch from initial commit
	if err := runGitCmd(t, repoDir, "branch", "feature"); err != nil {
		t.Fatalf("Failed to create branch: %v", err)
	}

	// Add a new file and commit it on main
	newFile := filepath.Join(repoDir, "new.txt")
	if err := os.WriteFile(newFile, []byte("new content"), 0600); err != nil {
		t.Fatalf("Failed to create new file: %v", err)
	}
	if err := runGitCmd(t, repoDir, "add", "new.txt"); err != nil {
		t.Fatalf("Failed to stage new file: %v", err)
	}
	if err := runGitCmd(t, repoDir, "commit", "-m", "Add new file"); err != nil {
		t.Fatalf("Failed to commit: %v", err)
	}

	// Test ref mode (compare against the feature branch)
	fl, err := GitChangedFiles(repoDir, ChangedOptions{Mode: ChangedModeRef, Ref: "feature"})
	if err != nil {
		t.Fatalf("GitChangedFiles failed: %v", err)
	}

	files := fl.Files()
	if len(files) != 1 {
		t.Errorf("expected 1 changed file since feature branch, got %d: %v", len(files), files)
	}
	if len(files) > 0 && files[0] != "new.txt" {
		t.Errorf("expected new.txt, got %s", files[0])
	}
}

func TestGitChangedFiles_DeletedExcluded(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	repoDir := setupGitRepo(t)

	// Delete the initial file
	if err := os.Remove(filepath.Join(repoDir, "initial.txt")); err != nil {
		t.Fatalf("Failed to delete file: %v", err)
	}

	// Test uncommitted mode - deleted file should NOT be included
	fl, err := GitChangedFiles(repoDir, ChangedOptions{Mode: ChangedModeUncommitted})
	if err != nil {
		// If no other changes, we expect ErrNoChangedFiles
		if errors.Is(err, ErrNoChangedFiles) {
			return // This is expected
		}
		t.Fatalf("GitChangedFiles failed: %v", err)
	}

	// If we get here, verify deleted file is not in the list
	for _, f := range fl.Files() {
		if f == "initial.txt" {
			t.Errorf("deleted file initial.txt should not be in changed files")
		}
	}
}

func TestGitChangedFiles_NotGitRepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	tmpDir := t.TempDir() // Not a git repo

	_, err := GitChangedFiles(tmpDir, ChangedOptions{Mode: ChangedModeUncommitted})
	if err == nil {
		t.Fatal("expected error for non-git directory")
	}
	if !errors.Is(err, ErrNotGitRepo) {
		t.Errorf("expected ErrNotGitRepo, got: %v", err)
	}
}

func TestGitChangedFiles_InvalidRef(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	repoDir := setupGitRepo(t)

	_, err := GitChangedFiles(repoDir, ChangedOptions{Mode: ChangedModeRef, Ref: "nonexistent-branch-xyz"})
	if err == nil {
		t.Fatal("expected error for invalid ref")
	}
	if !errors.Is(err, ErrRefNotFound) {
		t.Errorf("expected ErrRefNotFound, got: %v", err)
	}
}

func TestGitChangedFiles_NoChanges(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	repoDir := setupGitRepo(t)

	// No uncommitted changes
	_, err := GitChangedFiles(repoDir, ChangedOptions{Mode: ChangedModeUncommitted})
	if err == nil {
		t.Fatal("expected error when no changes")
	}
	if !errors.Is(err, ErrNoChangedFiles) {
		t.Errorf("expected ErrNoChangedFiles, got: %v", err)
	}
}

func TestGitChangedFiles_Subdirectory(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	repoDir := setupGitRepo(t)

	// Create subdirectory structure
	subDir := filepath.Join(repoDir, "src", "pkg")
	if err := os.MkdirAll(subDir, 0750); err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}

	// Create file in subdirectory
	subFile := filepath.Join(subDir, "helper.go")
	if err := os.WriteFile(subFile, []byte("package pkg"), 0600); err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	// Create file outside subdirectory (in repo root)
	rootFile := filepath.Join(repoDir, "root.go")
	if err := os.WriteFile(rootFile, []byte("package main"), 0600); err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	// Scan from subdirectory - should only include files within it
	fl, err := GitChangedFiles(filepath.Join(repoDir, "src"), ChangedOptions{Mode: ChangedModeUncommitted})
	if err != nil {
		t.Fatalf("GitChangedFiles failed: %v", err)
	}

	files := fl.Files()
	// Should only include pkg/helper.go (relative to src/), not root.go
	if len(files) != 1 {
		t.Errorf("expected 1 file in subdirectory, got %d: %v", len(files), files)
	}
	// Use filepath.FromSlash for cross-platform comparison (backslashes on Windows)
	expected := filepath.FromSlash("pkg/helper.go")
	if len(files) > 0 && files[0] != expected {
		t.Errorf("expected %s, got %s", expected, files[0])
	}
}

func TestGitChangedFiles_SpecialCharacters(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	repoDir := setupGitRepo(t)

	// Create file with spaces in name
	spaceFile := filepath.Join(repoDir, "file with spaces.txt")
	if err := os.WriteFile(spaceFile, []byte("content"), 0600); err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	fl, err := GitChangedFiles(repoDir, ChangedOptions{Mode: ChangedModeUncommitted})
	if err != nil {
		t.Fatalf("GitChangedFiles failed: %v", err)
	}

	files := fl.Files()
	found := false
	for _, f := range files {
		if f == "file with spaces.txt" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("file with spaces not found in changed files: %v", files)
	}
}

// TestGitChangedFiles_ControlCharFilename is the regression test for the
// scan-scope bypass: a changed file whose name contains a control character
// (here a tab) must appear in the changed set. Before the -z switch, git
// C-quoted such names ("weird\tname.txt") and newline splitting produced a
// string that no longer matched any on-disk file, so it was silently dropped
// while other changed files still uploaded.
func TestGitChangedFiles_ControlCharFilename(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	// Tabs/newlines in filenames are not permitted on Windows.
	if runtime.GOOS == "windows" {
		t.Skip("control characters not allowed in filenames on Windows")
	}

	repoDir := setupGitRepo(t)

	// Filename containing a tab (a control character git would normally quote).
	weirdName := "weird\tname.txt"
	if err := os.WriteFile(filepath.Join(repoDir, weirdName), []byte("content"), 0600); err != nil {
		t.Fatalf("failed to create control-char file: %v", err)
	}
	// A normal file alongside it, to prove we don't just detect one or the other.
	if err := os.WriteFile(filepath.Join(repoDir, "normal.go"), []byte("package main"), 0600); err != nil {
		t.Fatalf("failed to create normal file: %v", err)
	}

	fl, err := GitChangedFiles(repoDir, ChangedOptions{Mode: ChangedModeUncommitted})
	if err != nil {
		t.Fatalf("GitChangedFiles failed: %v", err)
	}

	files := fl.Files()
	fileSet := make(map[string]bool)
	for _, f := range files {
		fileSet[f] = true
	}
	if !fileSet[weirdName] {
		t.Errorf("control-char filename %q missing from changed set: %q", weirdName, files)
	}
	if !fileSet["normal.go"] {
		t.Errorf("normal.go missing from changed set: %q", files)
	}
}

// TestGitChangedFiles_ControlCharFilename_Newline covers a filename containing
// a literal newline — the byte that a newline-splitting parser fundamentally
// cannot represent as a single record.
func TestGitChangedFiles_ControlCharFilename_Newline(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	if runtime.GOOS == "windows" {
		t.Skip("newlines not allowed in filenames on Windows")
	}

	repoDir := setupGitRepo(t)

	weirdName := "line1\nline2.txt"
	if err := os.WriteFile(filepath.Join(repoDir, weirdName), []byte("content"), 0600); err != nil {
		t.Fatalf("failed to create newline file: %v", err)
	}

	fl, err := GitChangedFiles(repoDir, ChangedOptions{Mode: ChangedModeUncommitted})
	if err != nil {
		t.Fatalf("GitChangedFiles failed: %v", err)
	}

	found := false
	for _, f := range fl.Files() {
		if f == weirdName {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("newline filename %q missing from changed set: %q", weirdName, fl.Files())
	}
}

func TestFilterToScanPath(t *testing.T) {
	tests := []struct {
		name         string
		repoRoot     string
		scanPath     string
		changedPaths []string
		want         []string
	}{
		{
			name:         "same as repo root",
			repoRoot:     filepath.FromSlash("/repo"),
			scanPath:     filepath.FromSlash("/repo"),
			changedPaths: []string{"a.go", "b.go"},
			want:         []string{"a.go", "b.go"},
		},
		{
			name:         "subdirectory filter",
			repoRoot:     filepath.FromSlash("/repo"),
			scanPath:     filepath.FromSlash("/repo/src"),
			changedPaths: []string{"src/a.go", "src/pkg/b.go", "root.go"},
			want:         []string{"a.go", "pkg/b.go"},
		},
		{
			name:         "no matching files",
			repoRoot:     filepath.FromSlash("/repo"),
			scanPath:     filepath.FromSlash("/repo/other"),
			changedPaths: []string{"src/a.go"},
			want:         nil,
		},
		{
			name:         "nested subdirectory",
			repoRoot:     filepath.FromSlash("/repo"),
			scanPath:     filepath.FromSlash("/repo/src/pkg"),
			changedPaths: []string{"src/pkg/a.go", "src/other.go"},
			want:         []string{"a.go"},
		},
		{
			name:         "path traversal via dotdot excluded",
			repoRoot:     filepath.FromSlash("/repo"),
			scanPath:     filepath.FromSlash("/repo/src"),
			changedPaths: []string{"src/../secret"},
			want:         nil, // "../secret" after Clean is outside "src/"
		},
		{
			name:         "path traversal that resolves inside included",
			repoRoot:     filepath.FromSlash("/repo"),
			scanPath:     filepath.FromSlash("/repo/src"),
			changedPaths: []string{"src/pkg/../helper.go"},
			want:         []string{"helper.go"}, // "src/helper.go" after Clean is still inside "src/"
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := filterToScanPath(tt.repoRoot, tt.scanPath, tt.changedPaths)
			if err != nil {
				t.Fatalf("filterToScanPath() unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Errorf("filterToScanPath() = %v, want %v", got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("filterToScanPath()[%d] = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestFilterToScanPath_SymlinkEscape(t *testing.T) {
	tmpDir := t.TempDir()

	// Structure:
	// tmpDir/repo/src/legit.go      (real file)
	// tmpDir/repo/src/evil/         (symlink -> tmpDir/outside/)
	// tmpDir/outside/leaked.go      (file outside repo)
	repoRoot := filepath.Join(tmpDir, "repo")
	scanPath := filepath.Join(repoRoot, "src")
	outsideDir := filepath.Join(tmpDir, "outside")

	if err := os.MkdirAll(scanPath, 0o750); err != nil {
		t.Fatalf("failed to create scan path: %v", err)
	}
	if err := os.MkdirAll(outsideDir, 0o750); err != nil {
		t.Fatalf("failed to create outside dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(scanPath, "legit.go"), []byte("package main"), 0o600); err != nil {
		t.Fatalf("failed to write legit.go: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outsideDir, "leaked.go"), []byte("leaked"), 0o600); err != nil {
		t.Fatalf("failed to write leaked.go: %v", err)
	}

	// Create symlink: repo/src/evil -> outside/
	evilLink := filepath.Join(scanPath, "evil")
	if err := os.Symlink(outsideDir, evilLink); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	changedPaths := []string{
		"src/legit.go",       // legitimate file inside scan path
		"src/evil/leaked.go", // traverses via symlink to outside
	}

	filtered, err := filterToScanPath(repoRoot, scanPath, changedPaths)
	if err != nil {
		t.Fatalf("filterToScanPath error: %v", err)
	}

	if len(filtered) != 1 {
		t.Fatalf("expected 1 result, got %d: %v", len(filtered), filtered)
	}
	if filtered[0] != "legit.go" {
		t.Errorf("expected 'legit.go', got %q", filtered[0])
	}
}

func TestValidateRef(t *testing.T) {
	tests := []struct {
		name      string
		ref       string
		wantErr   bool
		errSubstr string
	}{
		{name: "valid branch name", ref: "main", wantErr: false},
		{name: "valid branch with slash", ref: "origin/main", wantErr: false},
		{name: "valid tag", ref: "v1.0.0", wantErr: false},
		{name: "valid commit hash", ref: "abc123def", wantErr: false},
		{name: "dash prefix rejected", ref: "-flag", wantErr: true, errSubstr: "cannot start with dash"},
		{name: "double dash rejected", ref: "--config", wantErr: true, errSubstr: "cannot start with dash"},
		{name: "newline rejected", ref: "main\n", wantErr: true, errSubstr: "whitespace/control"},
		{name: "tab rejected", ref: "main\tother", wantErr: true, errSubstr: "whitespace/control"},
		{name: "null byte rejected", ref: "main\x00", wantErr: true, errSubstr: "whitespace/control"},
		{name: "space rejected", ref: "main branch", wantErr: true, errSubstr: "whitespace/control"},
		{name: "carriage return rejected", ref: "main\r", wantErr: true, errSubstr: "whitespace/control"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRef(tt.ref)
			if tt.wantErr {
				if err == nil {
					t.Errorf("validateRef(%q) expected error containing %q, got nil", tt.ref, tt.errSubstr)
				} else if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("validateRef(%q) expected error containing %q, got %q", tt.ref, tt.errSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("validateRef(%q) unexpected error: %v", tt.ref, err)
				}
			}
		})
	}
}

func TestParseNulSeparated(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []string
		wantNil bool // expect nil
	}{
		{
			name:  "normal records",
			input: "a.go\x00b.go\x00c.go\x00",
			want:  []string{"a.go", "b.go", "c.go"},
		},
		{
			name:  "no trailing NUL",
			input: "a.go\x00b.go",
			want:  []string{"a.go", "b.go"},
		},
		{
			name:    "empty string",
			input:   "",
			wantNil: true,
		},
		{
			name:  "preserves spaces in filenames",
			input: "  a.go  \x00  b.go  \x00",
			want:  []string{"  a.go  ", "  b.go  "},
		},
		{
			// The core regression: control characters inside a pathname are
			// payload, not delimiters. Newline, CR, and tab must survive.
			name:  "control characters in filename preserved",
			input: "weird\tname.txt\x00has\nnewline.go\x00has\rcr.py\x00",
			want:  []string{"weird\tname.txt", "has\nnewline.go", "has\rcr.py"},
		},
		{
			name:  "empty records skipped",
			input: "a.go\x00\x00b.go\x00",
			want:  []string{"a.go", "b.go"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseNulSeparated(tt.input)
			if tt.wantNil {
				if got != nil {
					t.Errorf("parseNulSeparated() = %v, want nil", got)
				}
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("parseNulSeparated() = %q, want %q", got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("parseNulSeparated()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestCombineAndDedupe(t *testing.T) {
	tests := []struct {
		name  string
		lists [][]string
		want  []string
	}{
		{
			name:  "no duplicates",
			lists: [][]string{{"a.go", "b.go"}, {"c.go", "d.go"}},
			want:  []string{"a.go", "b.go", "c.go", "d.go"},
		},
		{
			name:  "with duplicates",
			lists: [][]string{{"a.go", "b.go"}, {"b.go", "c.go"}},
			want:  []string{"a.go", "b.go", "c.go"},
		},
		{
			name:  "empty inputs",
			lists: [][]string{nil, {"a.go"}},
			want:  []string{"a.go"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := combineAndDedupe(tt.lists...)
			if len(got) != len(tt.want) {
				t.Errorf("combineAndDedupe() = %v, want %v", got, tt.want)
				return
			}
			// Check all expected items are present (order may vary)
			gotSet := make(map[string]bool)
			for _, g := range got {
				gotSet[g] = true
			}
			for _, w := range tt.want {
				if !gotSet[w] {
					t.Errorf("combineAndDedupe() missing %v, got %v", w, got)
				}
			}
		})
	}
}
