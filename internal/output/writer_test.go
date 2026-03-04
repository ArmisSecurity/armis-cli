package output

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestFormatFromExtension(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "json extension",
			path:     "results.json",
			expected: "json",
		},
		{
			name:     "JSON uppercase extension",
			path:     "results.JSON",
			expected: "json",
		},
		{
			name:     "sarif extension",
			path:     "results.sarif",
			expected: "sarif",
		},
		{
			name:     "SARIF uppercase extension",
			path:     "results.SARIF",
			expected: "sarif",
		},
		{
			name:     "xml extension",
			path:     "results.xml",
			expected: "junit",
		},
		{
			name:     "txt extension (unrecognized)",
			path:     "results.txt",
			expected: "",
		},
		{
			name:     "no extension",
			path:     "results",
			expected: "",
		},
		{
			name:     "path with directories",
			path:     "/tmp/scans/output.json",
			expected: "json",
		},
		{
			name:     "path with multiple dots",
			path:     "scan.results.sarif",
			expected: "sarif",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatFromExtension(tt.path)
			if result != tt.expected {
				t.Errorf("FormatFromExtension(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}

func TestNewFileOutput(t *testing.T) {
	t.Run("creates file in temp directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "output.json")

		fo, err := NewFileOutput(path)
		if err != nil {
			t.Fatalf("NewFileOutput() error = %v", err)
		}
		defer func() { _ = fo.Close() }()

		// Verify file was created
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Error("expected file to be created")
		}
	})

	t.Run("creates file with restricted permissions", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "sensitive-output.json")

		fo, err := NewFileOutput(path)
		if err != nil {
			t.Fatalf("NewFileOutput() error = %v", err)
		}
		defer func() { _ = fo.Close() }()

		// Verify file has 0600 permissions (owner read/write only)
		// Skip permission check on Windows - Go doesn't preserve POSIX permission bits there
		if runtime.GOOS != osWindows {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("os.Stat() error = %v", err)
			}
			// Mask out the file type bits, check only permission bits
			perm := info.Mode().Perm()
			if perm != 0600 {
				t.Errorf("file permissions = %o, want 0600", perm)
			}
		}
	})

	t.Run("creates parent directories", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "nested", "dir", "output.json")

		fo, err := NewFileOutput(path)
		if err != nil {
			t.Fatalf("NewFileOutput() error = %v", err)
		}
		defer func() { _ = fo.Close() }()

		// Verify file and parent directories were created
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Error("expected file to be created with parent directories")
		}
	})

	t.Run("writer can write content", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "output.txt")

		fo, err := NewFileOutput(path)
		if err != nil {
			t.Fatalf("NewFileOutput() error = %v", err)
		}

		content := "test output content"
		_, err = fo.Writer().Write([]byte(content))
		if err != nil {
			t.Fatalf("Write() error = %v", err)
		}

		if err := fo.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}

		// Verify content was written
		// #nosec G304 -- test code reading from controlled temp directory
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile() error = %v", err)
		}
		if string(data) != content {
			t.Errorf("file content = %q, want %q", string(data), content)
		}
	})

	t.Run("error on invalid path", func(t *testing.T) {
		// Create a file (not a directory) to trigger ENOTDIR when MkdirAll tries
		// to create a directory at this path - portable across all platforms
		tmpDir := t.TempDir()
		blockingFile := filepath.Join(tmpDir, "notadir")
		if err := os.WriteFile(blockingFile, []byte("x"), 0600); err != nil {
			t.Fatalf("failed to create blocking file: %v", err)
		}
		// Try to create output file inside the file (ENOTDIR)
		path := filepath.Join(blockingFile, "output.json")

		_, err := NewFileOutput(path)
		if err == nil {
			t.Error("expected error for invalid path")
		}
	})

	t.Run("error on empty path", func(t *testing.T) {
		_, err := NewFileOutput("")
		if err == nil {
			t.Error("expected error for empty path")
		}
	})

	t.Run("rejects dangerous system paths", func(t *testing.T) {
		if runtime.GOOS == osWindows {
			t.Skip("dangerous path tests are Unix-specific")
		}

		dangerousPaths := []string{
			"/etc/passwd",
			"/etc/shadow",
			"/etc/hosts",
			"/etc/sudoers",
			"/etc/someconfig",
			"/boot/grub/grub.cfg",
			"/proc/self/exe",
			"/sys/kernel/debug",
			"/dev/null", // Even /dev paths should be rejected
		}

		for _, path := range dangerousPaths {
			t.Run(path, func(t *testing.T) {
				_, err := NewFileOutput(path)
				if err == nil {
					t.Errorf("expected error for dangerous path %s", path)
				}
			})
		}
	})
}

func TestFileOutputClose(t *testing.T) {
	t.Run("close returns nil for valid file", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "output.json")

		fo, err := NewFileOutput(path)
		if err != nil {
			t.Fatalf("NewFileOutput() error = %v", err)
		}

		if err := fo.Close(); err != nil {
			t.Errorf("Close() error = %v, want nil", err)
		}
	})

	t.Run("close on nil file returns nil", func(t *testing.T) {
		fo := &FileOutput{file: nil}
		if err := fo.Close(); err != nil {
			t.Errorf("Close() on nil file = %v, want nil", err)
		}
	})
}
