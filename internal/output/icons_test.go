package output

import "testing"

func TestGetConfidenceIcon(t *testing.T) {
	tests := []struct {
		name       string
		confidence int
		want       string
	}{
		// High confidence (>= 80)
		{name: "confidence 100", confidence: 100, want: IconSuccess},
		{name: "confidence 80 (boundary)", confidence: 80, want: IconSuccess},
		{name: "confidence 81", confidence: 81, want: IconSuccess},

		// Medium confidence (>= 50 && < 80)
		{name: "confidence 79 (boundary)", confidence: 79, want: "~"},
		{name: "confidence 50 (boundary)", confidence: 50, want: "~"},
		{name: "confidence 65", confidence: 65, want: "~"},

		// Low confidence (< 50)
		{name: "confidence 49 (boundary)", confidence: 49, want: "?"},
		{name: "confidence 0", confidence: 0, want: "?"},
		{name: "confidence negative", confidence: -1, want: "?"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetConfidenceIcon(tt.confidence)
			if got != tt.want {
				t.Errorf("GetConfidenceIcon(%d) = %q, want %q", tt.confidence, got, tt.want)
			}
		})
	}
}

func TestIconConstants(t *testing.T) {
	// Verify icon constants are non-empty
	if SeverityDot == "" {
		t.Error("SeverityDot should not be empty")
	}
	if IconDependency == "" {
		t.Error("IconDependency should not be empty")
	}
	if IconSuccess == "" {
		t.Error("IconSuccess should not be empty")
	}
	if IconPointer == "" {
		t.Error("IconPointer should not be empty")
	}
}
