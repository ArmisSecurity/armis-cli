package cli

import (
	"bytes"
	"os"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

func TestInitColors_Never(t *testing.T) {
	InitColors(ColorModeNever)
	if ColorsEnabled() {
		t.Error("expected colors to be disabled with ColorModeNever")
	}
	if ColorsForced() {
		t.Error("expected ColorsForced() to be false with ColorModeNever")
	}
	// Verify error label style renders without ANSI codes
	rendered := errorLabelStyle.Render("test")
	if bytes.Contains([]byte(rendered), []byte("\033[")) {
		t.Error("expected no ANSI codes when colors disabled")
	}
}

func TestInitColors_Always(t *testing.T) {
	// Set NO_COLOR to verify that 'always' overrides it
	t.Setenv("NO_COLOR", "1")

	InitColors(ColorModeAlways)
	if !ColorsEnabled() {
		t.Error("expected colors to be enabled with ColorModeAlways even when NO_COLOR is set")
	}
	if !ColorsForced() {
		t.Error("expected ColorsForced() to be true with ColorModeAlways")
	}
	// Verify error label style has colors (lipgloss styles contain color info)
	if errorLabelStyle.GetForeground() == nil {
		t.Error("expected errorLabelStyle to have foreground color set")
	}
}

func TestInitColors_Auto_NoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	InitColors(ColorModeAuto)
	if ColorsEnabled() {
		t.Error("expected colors to be disabled when NO_COLOR is set in auto mode")
	}
	if ColorsForced() {
		t.Error("expected ColorsForced() to be false with ColorModeAuto")
	}
}

func TestInitColors_Auto_DumbTerm(t *testing.T) {
	t.Setenv("TERM", "dumb")

	InitColors(ColorModeAuto)
	if ColorsEnabled() {
		t.Error("expected colors to be disabled when TERM=dumb in auto mode")
	}
}

// captureStderr captures stderr output during function execution
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stderr = w

	fn()

	if err := w.Close(); err != nil {
		t.Errorf("failed to close pipe writer: %v", err)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Errorf("failed to read from pipe: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Errorf("failed to close pipe reader: %v", err)
	}
	os.Stderr = oldStderr
	return buf.String()
}

func TestPrintError_WithColors(t *testing.T) {
	// Force ANSI color profile for test (lipgloss auto-detects pipe as no-color)
	lipgloss.SetColorProfile(termenv.ANSI256)
	InitColors(ColorModeAlways)

	output := captureStderr(t, func() {
		PrintError("test error message")
	})

	if !bytes.Contains([]byte(output), []byte("Error:")) {
		t.Errorf("expected output to contain 'Error:', got: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("test error message")) {
		t.Errorf("expected output to contain message, got: %s", output)
	}
	// Check for ANSI codes
	if !bytes.Contains([]byte(output), []byte("\033[")) {
		t.Error("expected output to contain ANSI escape codes when colors enabled")
	}
}

func TestPrintError_WithoutColors(t *testing.T) {
	InitColors(ColorModeNever)

	output := captureStderr(t, func() {
		PrintError("test error message")
	})

	if bytes.Contains([]byte(output), []byte("\033[")) {
		t.Error("expected output to NOT contain ANSI escape codes when colors disabled")
	}
	if output != "Error: test error message\n" {
		t.Errorf("expected plain 'Error: test error message\\n', got: %q", output)
	}
}

func TestPrintWarning_WithColors(t *testing.T) {
	InitColors(ColorModeAlways)

	output := captureStderr(t, func() {
		PrintWarning("test warning")
	})

	if !bytes.Contains([]byte(output), []byte("Warning:")) {
		t.Errorf("expected output to contain 'Warning:', got: %s", output)
	}
}

func TestPrintWarningf(t *testing.T) {
	InitColors(ColorModeNever)

	output := captureStderr(t, func() {
		PrintWarningf("file %s not found", "test.txt")
	})

	if output != "Warning: file test.txt not found\n" {
		t.Errorf("expected formatted warning, got: %q", output)
	}
}

func TestParseErrorMessage(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		expectedReason  string
		expectedContext string
	}{
		{
			name:            "API error with JSON detail",
			input:           `scan failed: failed to upload repository: upload failed after 674ms (tar size=1.6KiB, status=401 Unauthorized): {"detail":"Invalid authentication token"}`,
			expectedReason:  "Invalid authentication token",
			expectedContext: "scan failed: failed to upload repository: upload failed after 674ms (tar size=1.6KiB, status=401 Unauthorized)",
		},
		{
			name:            "API error with different detail",
			input:           `scan failed: failed to upload repository: upload failed after 500ms (tar size=2.0MiB, status=404 Not Found): {"detail":"Tenant not found"}`,
			expectedReason:  "Tenant not found",
			expectedContext: "scan failed: failed to upload repository: upload failed after 500ms (tar size=2.0MiB, status=404 Not Found)",
		},
		{
			name:            "plain error without JSON",
			input:           "API token required: use --token flag or ARMIS_API_TOKEN environment variable",
			expectedReason:  "API token required: use --token flag or ARMIS_API_TOKEN environment variable",
			expectedContext: "",
		},
		{
			name:            "error with context canceled",
			input:           "scan failed: context canceled",
			expectedReason:  "scan failed: context canceled",
			expectedContext: "",
		},
		{
			name:            "JSON without detail key",
			input:           `scan failed: upload failed: {"error":"something went wrong"}`,
			expectedReason:  `scan failed: upload failed: {"error":"something went wrong"}`,
			expectedContext: "",
		},
		{
			name:            "JSON with empty detail",
			input:           `scan failed: {"detail":""}`,
			expectedReason:  `scan failed: {"detail":""}`,
			expectedContext: "",
		},
		{
			name:            "malformed JSON",
			input:           `scan failed: {"detail":"unclosed`,
			expectedReason:  `scan failed: {"detail":"unclosed`,
			expectedContext: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, context := parseErrorMessage(tt.input)
			if reason != tt.expectedReason {
				t.Errorf("reason mismatch:\n  got:  %q\n  want: %q", reason, tt.expectedReason)
			}
			if context != tt.expectedContext {
				t.Errorf("context mismatch:\n  got:  %q\n  want: %q", context, tt.expectedContext)
			}
		})
	}
}

func TestPrintError_WithJSONDetail(t *testing.T) {
	InitColors(ColorModeNever)

	output := captureStderr(t, func() {
		PrintError(`scan failed: upload failed: {"detail":"Invalid token"}`)
	})

	expected := "Error: Invalid token\n  scan failed: upload failed\n"
	if output != expected {
		t.Errorf("expected:\n%q\ngot:\n%q", expected, output)
	}
}

func TestPrintError_PlainMessage(t *testing.T) {
	InitColors(ColorModeNever)

	output := captureStderr(t, func() {
		PrintError("simple error message")
	})

	expected := "Error: simple error message\n"
	if output != expected {
		t.Errorf("expected:\n%q\ngot:\n%q", expected, output)
	}
}
