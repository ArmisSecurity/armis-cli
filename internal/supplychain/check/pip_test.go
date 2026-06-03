package check

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestParsePipRequirements(t *testing.T) {
	t.Run("valid requirements.txt", func(t *testing.T) {
		entries, err := ParsePipRequirements(filepath.Join("testdata", "requirements.txt"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Name < entries[j].Name
		})

		expected := []PackageEntry{
			{Name: "celery", Version: "5.3.6"},
			{Name: "flask", Version: "3.0.0"},
			{Name: "my-cool-package", Version: "1.0.0"},
			{Name: "numpy", Version: "1.26.2"},
			{Name: "requests", Version: "2.31.0"},
			{Name: "sqlalchemy", Version: "2.0.23"},
			{Name: "typing-extensions", Version: "4.8.0"},
		}

		if len(entries) != len(expected) {
			t.Fatalf("expected %d entries, got %d: %v", len(expected), len(entries), entries)
		}

		for i, e := range entries {
			if e.Name != expected[i].Name || e.Version != expected[i].Version {
				t.Errorf("entry %d: expected %s@%s, got %s@%s", i, expected[i].Name, expected[i].Version, e.Name, e.Version)
			}
		}
	})

	t.Run("skips git and local installs", func(t *testing.T) {
		entries, err := ParsePipRequirements(filepath.Join("testdata", "requirements.txt"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for _, e := range entries {
			if e.Name == "mypkg" {
				t.Error("should have skipped git install")
			}
			if e.Name == "local-package" {
				t.Error("should have skipped local install")
			}
		}
	})

	t.Run("normalizes names", func(t *testing.T) {
		entries, err := ParsePipRequirements(filepath.Join("testdata", "requirements.txt"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for _, e := range entries {
			if e.Name == "my_cool_package" {
				t.Error("underscore should be normalized to hyphen")
			}
			if e.Name == testPkgSQLAlchemy {
				t.Error("name should be lowercased")
			}
		}
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := ParsePipRequirements("nonexistent.txt")
		if err == nil {
			t.Error("expected error for missing file")
		}
	})

	t.Run("parses lines longer than the default scanner token", func(t *testing.T) {
		// A pinned requirement followed by many "--hash" entries on a single
		// line-continuation-free line can exceed bufio.Scanner's default 64KB
		// token limit. Build a line well past that to assert the raised buffer
		// keeps such a lockfile parseable instead of failing "token too long".
		var sb strings.Builder
		sb.WriteString("flask==3.0.0 \\")
		for i := 0; i < 2000; i++ {
			sb.WriteString(" --hash=sha256:0000000000000000000000000000000000000000000000000000000000000000")
		}
		if sb.Len() <= bufio.MaxScanTokenSize {
			t.Fatalf("test line is %d bytes, expected > %d to exercise the raised buffer", sb.Len(), bufio.MaxScanTokenSize)
		}

		dir := t.TempDir()
		path := filepath.Join(dir, "requirements.txt")
		if err := os.WriteFile(path, []byte(sb.String()+"\n"), 0o600); err != nil {
			t.Fatalf("writing fixture: %v", err)
		}

		entries, err := ParsePipRequirements(path)
		if err != nil {
			t.Fatalf("unexpected error on long line: %v", err)
		}
		if len(entries) != 1 || entries[0].Name != "flask" || entries[0].Version != "3.0.0" {
			t.Errorf("expected [flask@3.0.0], got %v", entries)
		}
	})
}

func TestParsePipRequirement(t *testing.T) {
	tests := []struct {
		line     string
		wantName string
		wantVer  string
	}{
		{"flask==3.0.0", "flask", "3.0.0"},
		{"celery[redis]==5.3.6", "celery", "5.3.6"},
		{"typing-extensions==4.8.0 ; python_version < \"3.11\"", "typing-extensions", "4.8.0"},
		{"boto3>=1.28.0", "", ""},
		{"requests~=2.31", "", ""},
		{"", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			name, version := parsePipRequirement(tt.line)
			if name != tt.wantName || version != tt.wantVer {
				t.Errorf("parsePipRequirement(%q) = (%q, %q), want (%q, %q)", tt.line, name, version, tt.wantName, tt.wantVer)
			}
		})
	}
}

func TestNormalizePipName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Flask", "flask"},
		{"my_package", "my-package"},
		{"My.Package", "my-package"},
		{"requests", "requests"},
		// PEP 503 collapses runs of separators to a single hyphen.
		{"my__package", "my-package"},
		{"my.._package", "my-package"},
		{"a_-_b", "a-b"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizePipName(tt.input)
			if got != tt.want {
				t.Errorf("normalizePipName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
