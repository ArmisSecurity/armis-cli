package repo

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
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
			repoRoot:     "/repo",
			scanPath:     "/repo",
			changedPaths: []string{"a.go", "b.go"},
			want:         []string{"a.go", "b.go"},
		},
		{
			name:         "subdirectory filter",
			repoRoot:     "/repo",
			scanPath:     "/repo/src",
			changedPaths: []string{"src/a.go", "src/pkg/b.go", "root.go"},
			want:         []string{"a.go", "pkg/b.go"},
		},
		{
			name:         "no matching files",
			repoRoot:     "/repo",
			scanPath:     "/repo/other",
			changedPaths: []string{"src/a.go"},
			want:         nil,
		},
		{
			name:         "nested subdirectory",
			repoRoot:     "/repo",
			scanPath:     "/repo/src/pkg",
			changedPaths: []string{"src/pkg/a.go", "src/other.go"},
			want:         []string{"a.go"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterToScanPath(tt.repoRoot, tt.scanPath, tt.changedPaths)
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

func TestParseLines(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		want   []string
		wantNl bool // expect nil
	}{
		{
			name:  "normal lines",
			input: "a.go\nb.go\nc.go",
			want:  []string{"a.go", "b.go", "c.go"},
		},
		{
			name:  "trailing newline",
			input: "a.go\nb.go\n",
			want:  []string{"a.go", "b.go"},
		},
		{
			name:   "empty string",
			input:  "",
			wantNl: true,
		},
		{
			name:   "only whitespace",
			input:  "  \n  \n  ",
			wantNl: true,
		},
		{
			name:  "lines with spaces",
			input: "  a.go  \n  b.go  ",
			want:  []string{"a.go", "b.go"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseLines(tt.input)
			if tt.wantNl {
				if got != nil {
					t.Errorf("parseLines() = %v, want nil", got)
				}
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("parseLines() = %v, want %v", got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("parseLines()[%d] = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestCombineAndDedupe(t *testing.T) {
	tests := []struct {
		name    string
		outputs []string
		want    []string
	}{
		{
			name:    "no duplicates",
			outputs: []string{"a.go\nb.go", "c.go\nd.go"},
			want:    []string{"a.go", "b.go", "c.go", "d.go"},
		},
		{
			name:    "with duplicates",
			outputs: []string{"a.go\nb.go", "b.go\nc.go"},
			want:    []string{"a.go", "b.go", "c.go"},
		},
		{
			name:    "empty inputs",
			outputs: []string{"", "a.go"},
			want:    []string{"a.go"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := combineAndDedupe(tt.outputs...)
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
