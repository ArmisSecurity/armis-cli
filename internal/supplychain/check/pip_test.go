package check

import (
	"path/filepath"
	"sort"
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
			if e.Name == "SQLAlchemy" {
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
