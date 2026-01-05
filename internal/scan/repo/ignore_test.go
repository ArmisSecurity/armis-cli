package repo

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadIgnorePatterns(t *testing.T) {
	tmpDir := t.TempDir()

	ignoreContent := `# Test ignore file
*.log
node_modules/
*.tmp
!important.log
`
	ignoreFile := filepath.Join(tmpDir, ".armisignore")
	if err := os.WriteFile(ignoreFile, []byte(ignoreContent), 0600); err != nil {
		t.Fatalf("Failed to create test ignore file: %v", err)
	}

	matcher, err := LoadIgnorePatterns(tmpDir)
	if err != nil {
		t.Fatalf("LoadIgnorePatterns failed: %v", err)
	}

	if matcher == nil {
		t.Fatal("Expected non-nil matcher")
	}

	tests := []struct {
		path     string
		isDir    bool
		expected bool
	}{
		{"test.log", false, true},
		{"important.log", false, false},
		{"node_modules", true, true},
		{"src/main.go", false, false},
		{"temp.tmp", false, true},
	}

	for _, tt := range tests {
		result := matcher.Match(tt.path, tt.isDir)
		if result != tt.expected {
			t.Errorf("Match(%q, %v) = %v, want %v", tt.path, tt.isDir, result, tt.expected)
		}
	}
}

func TestLoadIgnorePatternsNoFile(t *testing.T) {
	tmpDir := t.TempDir()

	matcher, err := LoadIgnorePatterns(tmpDir)
	if err != nil {
		t.Fatalf("LoadIgnorePatterns failed: %v", err)
	}

	if matcher == nil {
		t.Fatal("Expected non-nil matcher even without ignore file")
	}

	if matcher.Match("test.log", false) {
		t.Error("Expected no match when no ignore file exists")
	}
}

func TestLoadIgnorePatternsNested(t *testing.T) {
	tmpDir := t.TempDir()

	rootIgnore := filepath.Join(tmpDir, ".armisignore")
	if err := os.WriteFile(rootIgnore, []byte("*.log\n"), 0600); err != nil {
		t.Fatalf("Failed to create root ignore file: %v", err)
	}

	subDir := filepath.Join(tmpDir, "subdir")
	if err := os.MkdirAll(subDir, 0750); err != nil {
		t.Fatalf("Failed to create subdir: %v", err)
	}

	subIgnore := filepath.Join(subDir, ".armisignore")
	if err := os.WriteFile(subIgnore, []byte("*.tmp\n"), 0600); err != nil {
		t.Fatalf("Failed to create sub ignore file: %v", err)
	}

	matcher, err := LoadIgnorePatterns(tmpDir)
	if err != nil {
		t.Fatalf("LoadIgnorePatterns failed: %v", err)
	}

	if !matcher.Match("test.log", false) {
		t.Error("Expected root pattern to match")
	}

	if !matcher.Match("subdir/test.tmp", false) {
		t.Error("Expected nested pattern to match")
	}
}
