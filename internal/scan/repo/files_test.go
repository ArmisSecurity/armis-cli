package repo

import (
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
