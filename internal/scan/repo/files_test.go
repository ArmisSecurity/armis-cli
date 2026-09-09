package repo

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseFileList(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main"), 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(tmpDir, "pkg"), 0750); err != nil {
		t.Fatalf("Failed to create test dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "pkg", "helper.go"), []byte("package pkg"), 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	tests := []struct {
		name    string
		files   []string
		wantLen int
		wantErr bool
	}{
		{
			name:    "valid relative paths",
			files:   []string{"main.go", "pkg/helper.go"},
			wantLen: 2,
			wantErr: false,
		},
		{
			name:    "path traversal rejected",
			files:   []string{"../etc/passwd"},
			wantErr: true,
		},
		{
			name:    "empty list",
			files:   []string{},
			wantLen: 0,
			wantErr: false,
		},
		{
			name:    "empty string in list is skipped",
			files:   []string{"main.go", "", "pkg/helper.go"},
			wantLen: 2,
			wantErr: false,
		},
		{
			name:    "absolute path converted to relative",
			files:   []string{filepath.Join(tmpDir, "main.go")},
			wantLen: 1,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl, err := ParseFileList(tmpDir, tt.files)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(fl.Files()) != tt.wantLen {
				t.Errorf("got %d files, want %d", len(fl.Files()), tt.wantLen)
			}
		})
	}
}

func TestFileListValidateExistence(t *testing.T) {
	tmpDir := t.TempDir()

	// Create one existing file
	if err := os.WriteFile(filepath.Join(tmpDir, "exists.go"), []byte("package main"), 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Create a directory to test directory skipping
	if err := os.MkdirAll(filepath.Join(tmpDir, "subdir"), 0750); err != nil {
		t.Fatalf("Failed to create test dir: %v", err)
	}

	fl, err := ParseFileList(tmpDir, []string{"exists.go", "missing.go", "subdir"})
	if err != nil {
		t.Fatalf("ParseFileList failed: %v", err)
	}

	existing, warnings := fl.ValidateExistence()

	if len(existing) != 1 {
		t.Errorf("expected 1 existing file, got %d", len(existing))
	}
	if existing[0] != "exists.go" {
		t.Errorf("expected exists.go, got %s", existing[0])
	}
	if len(warnings) != 2 {
		t.Errorf("expected 2 warnings (missing file + directory), got %d", len(warnings))
	}
}

func TestParseFileListPathTraversal(t *testing.T) {
	tmpDir := t.TempDir()

	traversalPaths := []string{
		"../etc/passwd",
		"foo/../../etc/passwd",
		"./foo/../../../etc/passwd",
	}

	for _, path := range traversalPaths {
		t.Run(path, func(t *testing.T) {
			_, err := ParseFileList(tmpDir, []string{path})
			if err == nil {
				t.Errorf("expected error for path traversal attempt: %s", path)
			}
		})
	}
}

func TestParseFileListAbsolutePathOutsideRepo(t *testing.T) {
	// Create two separate temp directories - one is the "repo root", the other is "outside"
	repoDir := t.TempDir()
	outsideDir := t.TempDir()

	// Create a file in the outside directory to get a real absolute path
	outsideFile := filepath.Join(outsideDir, "outside.go")
	if err := os.WriteFile(outsideFile, []byte("package outside"), 0600); err != nil {
		t.Fatalf("Failed to create outside file: %v", err)
	}

	// Test that an absolute path outside the repo root is rejected
	_, err := ParseFileList(repoDir, []string{outsideFile})
	if err == nil {
		t.Errorf("expected error for absolute path outside repo: %s", outsideFile)
	}
	// Verify the error message is clear about the issue
	if err != nil && !strings.Contains(err.Error(), "outside repository root") {
		t.Errorf("expected error message to mention 'outside repository root', got: %s", err.Error())
	}
}

func TestFileListRepoRoot(t *testing.T) {
	tmpDir := t.TempDir()

	fl, err := ParseFileList(tmpDir, []string{})
	if err != nil {
		t.Fatalf("ParseFileList failed: %v", err)
	}

	// RepoRoot should return an absolute path
	root := fl.RepoRoot()
	if !filepath.IsAbs(root) {
		t.Errorf("RepoRoot should return absolute path, got: %s", root)
	}
}

func TestFileListFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test file
	if err := os.WriteFile(filepath.Join(tmpDir, "test.go"), []byte("package main"), 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	fl, err := ParseFileList(tmpDir, []string{"test.go"})
	if err != nil {
		t.Fatalf("ParseFileList failed: %v", err)
	}

	files := fl.Files()
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}
	if files[0] != "test.go" {
		t.Errorf("expected test.go, got %s", files[0])
	}
}

func TestParseFileListMaxFilesLimit(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate more *distinct* files than the limit. This test used to repeat one
	// name MaxFiles+1 times, which no longer overflows now that addFile
	// de-duplicates -- it was passing because the old count was of arguments, not
	// of files.
	files := make([]string, MaxFiles+1)
	for i := range files {
		files[i] = fmt.Sprintf("file%d.go", i) // Doesn't need to exist for this test
	}

	_, err := ParseFileList(tmpDir, files)
	if err == nil {
		t.Errorf("expected error when exceeding MaxFiles limit (%d), got nil", MaxFiles)
	}
	if err != nil && !strings.Contains(err.Error(), "too many files") {
		t.Errorf("expected error message to mention 'too many files', got: %s", err.Error())
	}
	if err != nil && !errors.Is(err, ErrTooManyFiles) {
		t.Errorf("expected the error to match ErrTooManyFiles, got: %v", err)
	}
}

func TestParseFileListDeduplicates(t *testing.T) {
	// --include-files and the filenames a tool appends as trailing arguments name
	// the same thing, so a caller that merges the two lists hands the same path in
	// twice. A duplicate is one file and must neither be scanned twice nor spend
	// the MaxFiles budget twice.
	tmpDir := t.TempDir()
	for _, name := range []string{"a.go", "b.go"} {
		if err := os.WriteFile(filepath.Join(tmpDir, name), []byte("package main"), 0600); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}
	}

	// Every spelling below names one of two files: repeated verbatim, with a "./"
	// prefix, and as an absolute path.
	fl, err := ParseFileList(tmpDir, []string{"a.go", "b.go", "a.go", "./a.go", filepath.Join(tmpDir, "b.go")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := fl.Files(); len(got) != 2 {
		t.Errorf("expected 2 distinct files, got %d: %v", len(got), got)
	}
}

func TestParseFileListDuplicatesDoNotExhaustLimit(t *testing.T) {
	// The whole point of counting after de-duplication: a selection whose
	// argument count is well over MaxFiles but whose file count is 1.
	tmpDir := t.TempDir()

	files := make([]string, MaxFiles*3)
	for i := range files {
		files[i] = "only.go"
	}

	fl, err := ParseFileList(tmpDir, files)
	if err != nil {
		t.Fatalf("expected %d repeats of one path to be one file, got error: %v", len(files), err)
	}
	if got := fl.Files(); len(got) != 1 {
		t.Errorf("expected 1 file, got %d: %v", len(got), got)
	}
}

func TestParseFileListEmptyEntriesDoNotExhaustLimit(t *testing.T) {
	// A --include-files value with trailing or doubled commas produces empty
	// entries. They are skipped, so they must not count towards MaxFiles either.
	tmpDir := t.TempDir()

	files := make([]string, 0, MaxFiles+10)
	files = append(files, "real.go")
	for i := 0; i < MaxFiles+9; i++ {
		files = append(files, "")
	}

	fl, err := ParseFileList(tmpDir, files)
	if err != nil {
		t.Fatalf("expected empty entries to be skipped, got error: %v", err)
	}
	if got := fl.Files(); len(got) != 1 {
		t.Errorf("expected 1 file, got %d: %v", len(got), got)
	}
}

func TestParseFileListAtMaxFilesLimit(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate exactly MaxFiles distinct files (should succeed)
	files := make([]string, MaxFiles)
	for i := range files {
		files[i] = fmt.Sprintf("file%d.go", i) // Doesn't need to exist for this test
	}

	fl, err := ParseFileList(tmpDir, files)
	if err != nil {
		t.Errorf("expected success at exactly MaxFiles limit (%d), got error: %v", MaxFiles, err)
	}
	if fl != nil && len(fl.Files()) != MaxFiles {
		t.Errorf("expected %d files, got %d", MaxFiles, len(fl.Files()))
	}
}
