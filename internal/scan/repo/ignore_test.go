package repo

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

func TestLoadIgnorePatternsSymlinkRejected(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a real file that the symlink will point to.
	realFile := filepath.Join(tmpDir, "real-ignore")
	if err := os.WriteFile(realFile, []byte("*.log\n"), 0600); err != nil {
		t.Fatalf("Failed to create real ignore file: %v", err)
	}

	// Create a symlink named .armisignore pointing to the real file.
	symlinkPath := filepath.Join(tmpDir, ".armisignore")
	if err := os.Symlink(realFile, symlinkPath); err != nil {
		t.Skipf("Symlink creation not supported: %v", err)
	}

	_, err := LoadIgnorePatterns(tmpDir)
	if err == nil {
		t.Fatal("expected error for symlinked .armisignore file")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected 'symlink' error, got: %v", err)
	}
}

func TestLoadIgnorePatternsOversizedFile(t *testing.T) {
	tmpDir := t.TempDir()

	oversized := make([]byte, maxIgnoreFileSize+1)
	for i := range oversized {
		oversized[i] = 'a'
	}

	ignoreFile := filepath.Join(tmpDir, ".armisignore")
	if err := os.WriteFile(ignoreFile, oversized, 0600); err != nil {
		t.Fatalf("Failed to create oversized ignore file: %v", err)
	}

	_, err := LoadIgnorePatterns(tmpDir)
	if err == nil {
		t.Fatal("expected error for oversized .armisignore file")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("expected 'too large' error, got: %v", err)
	}
}

func TestLoadArmisIgnore_MixedFile(t *testing.T) {
	tmpDir := t.TempDir()

	content := `# Mixed .armisignore file
vendor/
*.log
node_modules/

# Suppression directives
cwe:798 -- Environment variables
severity:LOW -- Team policy
category:secrets
rule:CKV_AWS_18 -- Required for pipeline

# More path patterns
docs/
`
	ignoreFile := filepath.Join(tmpDir, ".armisignore")
	if err := os.WriteFile(ignoreFile, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to create ignore file: %v", err)
	}

	matcher, config, err := LoadArmisIgnore(tmpDir)
	if err != nil {
		t.Fatalf("LoadArmisIgnore failed: %v", err)
	}

	// Verify path patterns work
	if !matcher.Match("vendor/lib.go", false) {
		t.Error("Expected vendor/lib.go to match path pattern")
	}
	if !matcher.Match("test.log", false) {
		t.Error("Expected test.log to match path pattern")
	}
	if !matcher.Match("docs/readme.md", false) {
		t.Error("Expected docs/readme.md to match path pattern")
	}

	// Verify directives were parsed
	if config == nil {
		t.Fatal("Expected non-nil SuppressionConfig")
	}
	if len(config.CWEs) != 1 {
		t.Errorf("CWEs count = %d, want 1", len(config.CWEs))
	} else {
		if config.CWEs[0].Value != "798" {
			t.Errorf("CWE value = %q, want %q", config.CWEs[0].Value, "798")
		}
		if config.CWEs[0].Reason != "Environment variables" {
			t.Errorf("CWE reason = %q, want %q", config.CWEs[0].Reason, "Environment variables")
		}
	}
	if len(config.Severities) != 1 {
		t.Errorf("Severities count = %d, want 1", len(config.Severities))
	} else if config.Severities[0].Value != "LOW" {
		t.Errorf("Severity value = %q, want %q", config.Severities[0].Value, "LOW")
	}
	if len(config.Categories) != 1 {
		t.Errorf("Categories count = %d, want 1", len(config.Categories))
	} else if config.Categories[0].Value != "secrets" {
		t.Errorf("Category value = %q, want %q", config.Categories[0].Value, "secrets")
	}
	if len(config.Rules) != 1 {
		t.Errorf("Rules count = %d, want 1", len(config.Rules))
	} else if config.Rules[0].Value != "CKV_AWS_18" {
		t.Errorf("Rule value = %q, want %q", config.Rules[0].Value, "CKV_AWS_18")
	}
}

func TestLoadArmisIgnore_NoFile(t *testing.T) {
	tmpDir := t.TempDir()

	matcher, config, err := LoadArmisIgnore(tmpDir)
	if err != nil {
		t.Fatalf("LoadArmisIgnore failed: %v", err)
	}

	if matcher == nil {
		t.Fatal("Expected non-nil matcher")
	}
	if config != nil {
		t.Error("Expected nil config when no .armisignore exists")
	}
}

func TestLoadArmisIgnore_DirectivesOnlyFromRoot(t *testing.T) {
	tmpDir := t.TempDir()

	// Root .armisignore with directives
	rootContent := "cwe:798\n*.log\n"
	if err := os.WriteFile(filepath.Join(tmpDir, ".armisignore"), []byte(rootContent), 0600); err != nil {
		t.Fatal(err)
	}

	// Nested .armisignore with a directive-like line
	subDir := filepath.Join(tmpDir, "subdir")
	if err := os.MkdirAll(subDir, 0750); err != nil {
		t.Fatal(err)
	}
	nestedContent := "cwe:79\n*.tmp\n"
	if err := os.WriteFile(filepath.Join(subDir, ".armisignore"), []byte(nestedContent), 0600); err != nil {
		t.Fatal(err)
	}

	matcher, config, err := LoadArmisIgnore(tmpDir)
	if err != nil {
		t.Fatalf("LoadArmisIgnore failed: %v", err)
	}

	// Root directive should be parsed
	if config == nil {
		t.Fatal("Expected non-nil config")
	}
	if len(config.CWEs) != 1 {
		t.Fatalf("CWEs count = %d, want 1 (only root directives)", len(config.CWEs))
	}
	if config.CWEs[0].Value != "798" {
		t.Errorf("CWE value = %q, want %q", config.CWEs[0].Value, "798")
	}

	// Nested "cwe:79" should be treated as a path pattern (not a directive)
	// Path patterns from both files should work
	if !matcher.Match("test.log", false) {
		t.Error("Expected test.log to match root pattern")
	}
	if !matcher.Match("subdir/test.tmp", false) {
		t.Error("Expected subdir/test.tmp to match nested pattern")
	}
}

func TestLoadArmisIgnore_LineLimitTruncation(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a file with 1005 lines: 1000 path patterns + 5 directives after the limit.
	// Using \n-joined content ensures exactly 1005 lines after TrimSuffix+Split.
	var lines []string
	for i := range 1000 {
		lines = append(lines, fmt.Sprintf("pattern_%d/", i))
	}
	// These directives should be truncated (beyond line 1000)
	lines = append(lines, "cwe:798", "cwe:79", "cwe:89", "cwe:22", "cwe:502")

	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(tmpDir, ".armisignore"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	_, config, err := LoadArmisIgnore(tmpDir)
	if err != nil {
		t.Fatalf("LoadArmisIgnore failed: %v", err)
	}

	// Directives after line 1000 should not be parsed
	if config != nil {
		t.Errorf("Expected nil config (directives were beyond line limit), got %d CWEs", len(config.CWEs))
	}
}

func TestLoadArmisIgnore_InvalidDirectiveNotPathPattern(t *testing.T) {
	tmpDir := t.TempDir()

	// An invalid directive (severity:BOGUS) should NOT become a path pattern
	content := "severity:BOGUS\nvendor/\n"
	if err := os.WriteFile(filepath.Join(tmpDir, ".armisignore"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	matcher, config, err := LoadArmisIgnore(tmpDir)
	if err != nil {
		t.Fatalf("LoadArmisIgnore failed: %v", err)
	}

	// Invalid directive should not produce a suppression
	if config != nil {
		t.Error("Expected nil config for invalid directive")
	}

	// "severity:BOGUS" should NOT be treated as a path pattern
	if matcher.Match("severity:BOGUS", false) {
		t.Error("Invalid directive should not become a path pattern")
	}

	// Valid path pattern should still work
	if !matcher.Match("vendor/lib.go", false) {
		t.Error("Expected vendor/lib.go to match")
	}
}

func TestLoadArmisIgnore_UTF8BOM(t *testing.T) {
	tmpDir := t.TempDir()

	// UTF-8 BOM + content
	bom := []byte{0xEF, 0xBB, 0xBF}
	content := append(bom, []byte("cwe:798\nvendor/\n")...)
	if err := os.WriteFile(filepath.Join(tmpDir, ".armisignore"), content, 0600); err != nil {
		t.Fatal(err)
	}

	matcher, config, err := LoadArmisIgnore(tmpDir)
	if err != nil {
		t.Fatalf("LoadArmisIgnore failed: %v", err)
	}

	if config == nil {
		t.Fatal("Expected non-nil config")
	}
	if len(config.CWEs) != 1 {
		t.Fatalf("CWEs count = %d, want 1", len(config.CWEs))
	}
	if config.CWEs[0].Value != "798" {
		t.Errorf("CWE value = %q, want %q", config.CWEs[0].Value, "798")
	}
	if !matcher.Match("vendor/lib.go", false) {
		t.Error("Expected vendor/lib.go to match")
	}
}

func TestLoadArmisIgnore_BackwardCompat(t *testing.T) {
	// Verify LoadIgnorePatterns and LoadArmisIgnore produce identical matchers
	tmpDir := t.TempDir()

	content := "*.log\nnode_modules/\n!important.log\n"
	if err := os.WriteFile(filepath.Join(tmpDir, ".armisignore"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	oldMatcher, err := LoadIgnorePatterns(tmpDir)
	if err != nil {
		t.Fatalf("LoadIgnorePatterns failed: %v", err)
	}

	newMatcher, _, newErr := LoadArmisIgnore(tmpDir)
	if newErr != nil {
		t.Fatalf("LoadArmisIgnore failed: %v", newErr)
	}

	paths := []struct {
		path  string
		isDir bool
	}{
		{"test.log", false},
		{"important.log", false},
		{"node_modules", true},
		{"src/main.go", false},
	}

	for _, p := range paths {
		oldResult := oldMatcher.Match(p.path, p.isDir)
		newResult := newMatcher.Match(p.path, p.isDir)
		if oldResult != newResult {
			t.Errorf("Match(%q, %v): LoadIgnorePatterns=%v, LoadArmisIgnore=%v",
				p.path, p.isDir, oldResult, newResult)
		}
	}
}
