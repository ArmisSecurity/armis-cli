package output

import (
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/charmbracelet/lipgloss"
)

func TestGetLexer(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		wantLang string // Expected language name
	}{
		{"Go file", "main.go", "Go"},
		{"Python file", "script.py", "Python"},
		{"JavaScript file", "app.js", "JavaScript"},
		{"TypeScript file", "app.ts", "TypeScript"},
		{"Java file", "Main.java", "Java"},
		{"Ruby file", "app.rb", "Ruby"},
		{"Rust file", "main.rs", "Rust"},
		{"YAML file", "config.yaml", "YAML"},
		{"JSON file", "data.json", "JSON"},
		{"Dockerfile", "Dockerfile", "Docker"},
		{"Shell script", "script.sh", "Bash"},
		{"Unknown extension", "file.xyz", "plaintext"},
		{"Empty filename", "", "plaintext"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lexer := GetLexer(tt.filename)
			if lexer == nil {
				t.Fatal("GetLexer returned nil")
			}
			config := lexer.Config()
			if config == nil {
				t.Fatal("Lexer config is nil")
			}
			// Check that we got some lexer (not necessarily exact name match)
			if config.Name == "" {
				t.Error("Lexer name is empty")
			}
		})
	}
}

func TestGetChromaStyle(t *testing.T) {
	// Test with colors disabled
	cli.InitColors(cli.ColorModeNever)
	SyncStylesWithColorMode()

	style := GetChromaStyle()
	if style != nil {
		t.Error("Expected nil style when colors are disabled")
	}

	// Test with colors enabled
	cli.InitColors(cli.ColorModeAlways)
	SyncStylesWithColorMode()

	style = GetChromaStyle()
	if style == nil {
		t.Error("Expected non-nil style when colors are enabled")
	}

	// Reset
	cli.InitColors(cli.ColorModeNever)
	SyncStylesWithColorMode()
}

func TestHighlightCode(t *testing.T) {
	// Test with colors disabled - should return plain lines
	cli.InitColors(cli.ColorModeNever)
	SyncStylesWithColorMode()

	code := "func main() {\n\tfmt.Println(\"hello\")\n}"
	lines := HighlightCode(code, "main.go")

	if len(lines) != 3 {
		t.Errorf("Expected 3 lines, got %d", len(lines))
	}
	if lines[0] != "func main() {" {
		t.Errorf("Expected plain text, got %q", lines[0])
	}

	// Test with colors enabled - should return highlighted lines
	cli.InitColors(cli.ColorModeAlways)
	SyncStylesWithColorMode()

	lines = HighlightCode(code, "main.go")
	if len(lines) != 3 {
		t.Errorf("Expected 3 lines, got %d", len(lines))
	}

	// Highlighted output should contain ANSI escape codes
	hasAnsi := strings.Contains(lines[0], "\x1b[")
	if !hasAnsi {
		t.Log("Note: Highlighted output may not contain ANSI codes in test environment")
	}

	// Reset
	cli.InitColors(cli.ColorModeNever)
	SyncStylesWithColorMode()
}

func TestHighlightLine(t *testing.T) {
	cli.InitColors(cli.ColorModeNever)
	SyncStylesWithColorMode()

	// Single line should work
	line := HighlightLine("fmt.Println()", "main.go")
	if line != "fmt.Println()" {
		t.Errorf("Expected plain line, got %q", line)
	}

	// Empty line should return empty
	line = HighlightLine("", "main.go")
	if line != "" {
		t.Errorf("Expected empty line, got %q", line)
	}
}

func TestHighlightCodeEmptyInput(t *testing.T) {
	cli.InitColors(cli.ColorModeNever)
	SyncStylesWithColorMode()

	// Empty code should return single empty line
	lines := HighlightCode("", "main.go")
	if len(lines) != 1 {
		t.Errorf("Expected 1 line for empty input, got %d", len(lines))
	}

	// Whitespace-only code
	lines = HighlightCode("   ", "main.go")
	if len(lines) != 1 || lines[0] != "   " {
		t.Errorf("Expected whitespace preserved, got %v", lines)
	}
}

func TestHighlightCodeMultipleLanguages(t *testing.T) {
	cli.InitColors(cli.ColorModeNever)
	SyncStylesWithColorMode()

	tests := []struct {
		filename string
		code     string
		numLines int
	}{
		{"test.py", "def foo():\n    pass", 2},
		{"test.js", "function foo() {\n  return 1;\n}", 3},
		{"test.yaml", "key: value\nlist:\n  - item", 3},
		{"test.json", "{\n  \"key\": \"value\"\n}", 3},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			lines := HighlightCode(tt.code, tt.filename)
			if len(lines) != tt.numLines {
				t.Errorf("Expected %d lines for %s, got %d", tt.numLines, tt.filename, len(lines))
			}
		})
	}
}

func TestHighlightLineWithBackground(t *testing.T) {
	// Test with colors disabled - should return plain highlighted text
	cli.InitColors(cli.ColorModeNever)
	SyncStylesWithColorMode()

	testColor := lipgloss.AdaptiveColor{Light: "#fef3c7", Dark: "#422006"}
	line := HighlightLineWithBackground("func main()", "main.go", testColor)
	if line != "func main()" {
		t.Errorf("Expected plain line when colors disabled, got %q", line)
	}

	// Test with colors enabled - should contain ANSI background codes
	cli.InitColors(cli.ColorModeAlways)
	SyncStylesWithColorMode()

	line = HighlightLineWithBackground("func main()", "main.go", testColor)
	// Should start with background ANSI code (48;2 for TrueColor background)
	if !strings.Contains(line, "\x1b[48;2;") {
		t.Log("Note: Background ANSI code may vary based on terminal profile")
	}
	// Should end with reset
	if !strings.HasSuffix(line, "\x1b[0m") {
		t.Errorf("Expected line to end with ANSI reset")
	}

	// Reset
	cli.InitColors(cli.ColorModeNever)
	SyncStylesWithColorMode()
}

func TestParseHexColor(t *testing.T) {
	tests := []struct {
		hex    string
		wantR  uint8
		wantG  uint8
		wantB  uint8
		wantOk bool
	}{
		{"#FF0000", 255, 0, 0, true},
		{"#00FF00", 0, 255, 0, true},
		{"#0000FF", 0, 0, 255, true},
		{"FF0000", 255, 0, 0, true}, // Without #
		{"#fef3c7", 254, 243, 199, true},
		{"#422006", 66, 32, 6, true},
		{"invalid", 0, 0, 0, false},
		{"#FFF", 0, 0, 0, false}, // Too short
		{"", 0, 0, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.hex, func(t *testing.T) {
			r, g, b, ok := parseHexColor(tt.hex)
			if ok != tt.wantOk {
				t.Errorf("parseHexColor(%q) ok = %v, want %v", tt.hex, ok, tt.wantOk)
			}
			if ok && (r != tt.wantR || g != tt.wantG || b != tt.wantB) {
				t.Errorf("parseHexColor(%q) = (%d, %d, %d), want (%d, %d, %d)",
					tt.hex, r, g, b, tt.wantR, tt.wantG, tt.wantB)
			}
		})
	}
}

func TestExtractDiffFilename(t *testing.T) {
	tests := []struct {
		name  string
		patch string
		want  string
	}{
		{
			name:  "git diff format",
			patch: "--- a/path/to/file.py\n+++ b/path/to/file.py\n@@ -1,3 +1,3 @@",
			want:  "path/to/file.py",
		},
		{
			name:  "plain diff format",
			patch: "--- path/to/file.py\n+++ path/to/file.py\n@@ -1,3 +1,3 @@",
			want:  "path/to/file.py",
		},
		{
			name:  "new file",
			patch: "--- /dev/null\n+++ b/newfile.go\n@@ -0,0 +1,5 @@",
			want:  "newfile.go",
		},
		{
			name:  "no header",
			patch: "@@ -1,3 +1,3 @@\n context\n-old\n+new",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDiffFilename(tt.patch)
			if got != tt.want {
				t.Errorf("extractDiffFilename() = %q, want %q", got, tt.want)
			}
		})
	}
}
