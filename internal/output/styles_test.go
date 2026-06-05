package output

import (
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

func TestGetSeverityText(t *testing.T) {
	styles := DefaultStyles()

	tests := []struct {
		name     string
		severity model.Severity
		wantNil  bool
	}{
		{name: "critical", severity: model.SeverityCritical, wantNil: false},
		{name: "high", severity: model.SeverityHigh, wantNil: false},
		{name: "medium", severity: model.SeverityMedium, wantNil: false},
		{name: "low", severity: model.SeverityLow, wantNil: false},
		{name: "info", severity: model.SeverityInfo, wantNil: false},
		{name: "unknown severity", severity: model.Severity("UNKNOWN"), wantNil: false},
		{name: "empty severity", severity: model.Severity(""), wantNil: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			style := styles.GetSeverityText(tt.severity)
			// Style should never be zero value
			rendered := style.Render("test")
			if rendered == "" {
				t.Errorf("GetSeverityText(%q) rendered empty string", tt.severity)
			}
		})
	}
}

func TestGetSeverityText_ReturnsDistinctStyles(t *testing.T) {
	styles := DefaultStyles()

	// Each severity should return a distinct style (not all the same)
	severities := []model.Severity{
		model.SeverityCritical,
		model.SeverityHigh,
		model.SeverityMedium,
		model.SeverityLow,
		model.SeverityInfo,
	}

	// Collect rendered outputs
	rendered := make(map[string]model.Severity)
	for _, sev := range severities {
		style := styles.GetSeverityText(sev)
		output := style.Render("X")
		if existing, ok := rendered[output]; ok && existing != sev {
			// Note: This might be acceptable for some severities in NoColorStyles
			// but in DefaultStyles they should be distinct
			t.Logf("Warning: %s and %s rendered identically", existing, sev)
		}
		rendered[output] = sev
	}
}

func TestGetSeverityText_UnknownFallsBackToInfo(t *testing.T) {
	styles := DefaultStyles()

	unknownStyle := styles.GetSeverityText(model.Severity("UNKNOWN"))
	infoStyle := styles.GetSeverityText(model.SeverityInfo)

	// Both should render the same (default case falls through to InfoText)
	unknownRendered := unknownStyle.Render("test")
	infoRendered := infoStyle.Render("test")

	if unknownRendered != infoRendered {
		t.Errorf("Unknown severity should fall back to Info style")
	}
}

func TestTerminalWidth(t *testing.T) {
	// In test environment (non-TTY), TerminalWidth should return the fallback
	width := TerminalWidth()

	// Should return a value within bounds
	if width < MinBoxWidth {
		t.Errorf("TerminalWidth() = %d, want >= %d", width, MinBoxWidth)
	}
	if width > MaxBoxWidth {
		t.Errorf("TerminalWidth() = %d, want <= %d", width, MaxBoxWidth)
	}

	// In pipe/test context, should return BoxWidth (the fallback)
	if width != BoxWidth {
		t.Logf("TerminalWidth() = %d (expected %d in non-TTY)", width, BoxWidth)
	}
}

func TestBoxWidthConstants(t *testing.T) {
	// Verify constant relationships
	if MinBoxWidth > BoxWidth {
		t.Errorf("MinBoxWidth (%d) should be <= BoxWidth (%d)", MinBoxWidth, BoxWidth)
	}
	if BoxWidth > MaxBoxWidth {
		t.Errorf("BoxWidth (%d) should be <= MaxBoxWidth (%d)", BoxWidth, MaxBoxWidth)
	}
	if BoxPadding < 0 {
		t.Errorf("BoxPadding should be non-negative, got %d", BoxPadding)
	}
}

func TestDefaultStyles_AllFieldsInitialized(t *testing.T) {
	styles := DefaultStyles()

	// Test that key style fields render without panicking
	testCases := []struct {
		name  string
		style func() string
	}{
		{"CriticalBadge", func() string { return styles.CriticalBadge.Render("X") }},
		{"HighBadge", func() string { return styles.HighBadge.Render("X") }},
		{"MediumBadge", func() string { return styles.MediumBadge.Render("X") }},
		{"LowBadge", func() string { return styles.LowBadge.Render("X") }},
		{"InfoBadge", func() string { return styles.InfoBadge.Render("X") }},
		{"CriticalText", func() string { return styles.CriticalText.Render("X") }},
		{"SuccessText", func() string { return styles.SuccessText.Render("X") }},
		{"ErrorText", func() string { return styles.ErrorText.Render("X") }},
		{"DiffAdd", func() string { return styles.DiffAdd.Render("X") }},
		{"DiffRemove", func() string { return styles.DiffRemove.Render("X") }},
		{"SpinnerChar", func() string { return styles.SpinnerChar.Render("X") }},
		{"HelpHeading", func() string { return styles.HelpHeading.Render("X") }},
		{"HelpCommand", func() string { return styles.HelpCommand.Render("X") }},
		{"HelpFlag", func() string { return styles.HelpFlag.Render("X") }},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.style()
			if result == "" {
				t.Errorf("%s rendered empty string", tc.name)
			}
		})
	}
}

func TestNoColorStyles_AllFieldsPlain(t *testing.T) {
	styles := NoColorStyles()

	// NoColorStyles should render text without ANSI codes
	testCases := []struct {
		name  string
		style func() string
	}{
		{"CriticalBadge", func() string { return styles.CriticalBadge.Render("test") }},
		{"HighBadge", func() string { return styles.HighBadge.Render("test") }},
		{"CriticalText", func() string { return styles.CriticalText.Render("test") }},
		{"SuccessText", func() string { return styles.SuccessText.Render("test") }},
		{"HelpHeading", func() string { return styles.HelpHeading.Render("test") }},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.style()
			// Should render as plain "test" without ANSI codes
			if result != "test" {
				t.Errorf("%s should render plain text, got %q", tc.name, result)
			}
		})
	}
}

func TestRenderCodeBlock(t *testing.T) {
	// NoColorStyles renders without ANSI escapes, so we can assert on the exact
	// text layout (gutter prefix, indentation) deterministically.
	styles := NoColorStyles()

	t.Run("prefixes every line with a gutter and indent", func(t *testing.T) {
		out := styles.RenderCodeBlock("npm() {\n  command foo\n}")
		lines := strings.Split(out, "\n")
		want := []string{
			"  " + IconGutter + " npm() {",
			"  " + IconGutter + "   command foo",
			"  " + IconGutter + " }",
		}
		if len(lines) != len(want) {
			t.Fatalf("got %d lines, want %d: %q", len(lines), len(want), out)
		}
		for i := range want {
			if lines[i] != want[i] {
				t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
			}
		}
	})

	t.Run("trims leading and trailing blank lines", func(t *testing.T) {
		// A snippet that ends in "\n" (as the shell wrapper does) must not emit a
		// trailing empty gutter row — that was the stray blank line before the
		// confirmation prompt.
		out := styles.RenderCodeBlock("\nfoo\n")
		if out != "  "+IconGutter+" foo" {
			t.Errorf("got %q, want a single gutter line with no surrounding blanks", out)
		}
	})

	t.Run("does not pad short lines to the longest line width", func(t *testing.T) {
		// The original bug: a long absolute path forced every other line to be
		// right-padded with spaces, producing a rectangle of trailing whitespace.
		out := styles.RenderCodeBlock("short\n" + strings.Repeat("x", 100))
		for _, ln := range strings.Split(out, "\n") {
			if strings.HasSuffix(ln, " ") {
				t.Errorf("line has trailing whitespace (block padding regressed): %q", ln)
			}
		}
	})

	t.Run("preserves interior blank lines", func(t *testing.T) {
		// Blank lines inside the snippet (e.g. between config sections) are kept so
		// the preview matches the file that gets written.
		out := styles.RenderCodeBlock("a\n\nb")
		lines := strings.Split(out, "\n")
		if len(lines) != 3 {
			t.Fatalf("got %d lines, want 3: %q", len(lines), out)
		}
		if lines[1] != "  "+IconGutter+" " {
			t.Errorf("interior blank line = %q, want a gutter with empty content", lines[1])
		}
	})
}
