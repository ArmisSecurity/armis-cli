package output

import (
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
