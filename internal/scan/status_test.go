package scan

import (
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

func TestFormatScanStatus(t *testing.T) {
	tests := []struct {
		name          string
		status        string
		inProgressMsg string
		want          string
	}{
		{"initiated", "INITIATED", "Scanning...", "Scan initiated, preparing analysis..."},
		{"initiated lowercase", "initiated", "Scanning...", "Scan initiated, preparing analysis..."},
		{"in_progress", "IN_PROGRESS", "Analyzing code...", "Analyzing code..."},
		{"in_progress lowercase", "in_progress", "Scanning image...", "Scanning image..."},
		{"completed", "COMPLETED", "Scanning...", "Scan completed, preparing results..."},
		{"failed", "FAILED", "Scanning...", "Scan encountered an error"},
		{"stopped", "STOPPED", "Scanning...", "Scan was stopped"},
		{"unknown", "UNKNOWN", "Scanning...", "Scanning... [UNKNOWN]"},
		{"empty", "", "Scanning...", "Scanning... []"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatScanStatus(tt.status, tt.inProgressMsg)
			if got != tt.want {
				t.Errorf("FormatScanStatus(%q, %q) = %q, want %q", tt.status, tt.inProgressMsg, got, tt.want)
			}
		})
	}
}

func TestFormatElapsed(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		want     string
	}{
		{"zero", 0, "0s"},
		{"seconds only", 45 * time.Second, "45s"},
		{"exactly one minute", 60 * time.Second, "1m 0s"},
		{"minutes and seconds", 2*time.Minute + 30*time.Second, "2m 30s"},
		{"rounds to nearest second", 45*time.Second + 500*time.Millisecond, "46s"},
		{"rounds down", 45*time.Second + 400*time.Millisecond, "45s"},
		{"large duration", 10*time.Minute + 5*time.Second, "10m 5s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatElapsed(tt.duration)
			if got != tt.want {
				t.Errorf("FormatElapsed(%v) = %q, want %q", tt.duration, got, tt.want)
			}
		})
	}
}

func TestMapSeverity(t *testing.T) {
	tests := []struct {
		name     string
		severity string
		want     model.Severity
	}{
		{"critical", "CRITICAL", model.SeverityCritical},
		{"critical lowercase", "critical", model.SeverityCritical},
		{"high", "HIGH", model.SeverityHigh},
		{"high mixed case", "High", model.SeverityHigh},
		{"medium", "MEDIUM", model.SeverityMedium},
		{"low", "LOW", model.SeverityLow},
		{"unknown", "UNKNOWN", model.SeverityInfo},
		{"empty", "", model.SeverityInfo},
		{"info", "INFO", model.SeverityInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MapSeverity(tt.severity)
			if got != tt.want {
				t.Errorf("MapSeverity(%q) = %v, want %v", tt.severity, got, tt.want)
			}
		})
	}
}
