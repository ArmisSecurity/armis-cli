package cli

import (
	"bytes"
	"os"
	"testing"
)

func TestInitColors_Never(t *testing.T) {
	InitColors(ColorModeNever)
	if ColorsEnabled() {
		t.Error("expected colors to be disabled with ColorModeNever")
	}
	if colorRed != "" || colorYellow != "" || colorBold != "" || colorReset != "" {
		t.Error("expected all color codes to be empty strings")
	}
}

func TestInitColors_Always(t *testing.T) {
	// Set NO_COLOR to verify that 'always' overrides it
	t.Setenv("NO_COLOR", "1")

	InitColors(ColorModeAlways)
	if !ColorsEnabled() {
		t.Error("expected colors to be enabled with ColorModeAlways even when NO_COLOR is set")
	}
	if colorRed == "" {
		t.Error("expected colorRed to have ANSI code")
	}
}

func TestInitColors_Auto_NoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	InitColors(ColorModeAuto)
	if ColorsEnabled() {
		t.Error("expected colors to be disabled when NO_COLOR is set in auto mode")
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
	os.Stderr = oldStderr
	return buf.String()
}

func TestPrintError_WithColors(t *testing.T) {
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
