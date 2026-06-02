package supplychain

import (
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{"72h", 72 * time.Hour, false},
		{"3d", 3 * 24 * time.Hour, false},
		{"1w", 7 * 24 * time.Hour, false},
		{"30m", 30 * time.Minute, false},
		{"1.5d", 36 * time.Hour, false},
		{"", 0, true},
		{"abc", 0, true},
		{"xd", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseDuration(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDuration(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.expected {
				t.Errorf("ParseDuration(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestClassifySeverity(t *testing.T) {
	threshold := 72 * time.Hour
	tests := []struct {
		age      time.Duration
		expected model.Severity
	}{
		{1 * time.Hour, model.SeverityHigh},
		{12 * time.Hour, model.SeverityHigh},
		{23 * time.Hour, model.SeverityHigh},
		{25 * time.Hour, model.SeverityMedium},
		{48 * time.Hour, model.SeverityMedium},
		{71 * time.Hour, model.SeverityMedium},
	}

	for _, tt := range tests {
		t.Run(tt.age.String(), func(t *testing.T) {
			got := ClassifySeverity(tt.age, threshold)
			if got != tt.expected {
				t.Errorf("ClassifySeverity(%v, %v) = %v, want %v", tt.age, threshold, got, tt.expected)
			}
		})
	}
}

func TestPolicyIsExcluded(t *testing.T) {
	policy := Policy{
		Exclusions: []string{"@myorg/*", "typescript"},
	}

	tests := []struct {
		name     string
		excluded bool
	}{
		{"@myorg/utils", true},
		{"@myorg/core", true},
		{"typescript", true},
		{"express", false},
		{"@other/pkg", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := policy.IsExcluded(tt.name)
			if got != tt.excluded {
				t.Errorf("IsExcluded(%q) = %v, want %v", tt.name, got, tt.excluded)
			}
		})
	}
}

// TestPolicyIsExcluded_ForwardSlashSemantics verifies that exclusion matching
// treats '/' as a literal path separator consistently (path.Match), so a
// non-slash pattern never matches a scoped package and a wildcard does not
// cross the scope separator. This must hold on every OS, including Windows.
func TestPolicyIsExcluded_ForwardSlashSemantics(t *testing.T) {
	tests := []struct {
		pattern  string
		name     string
		excluded bool
	}{
		// A single '*' must not span the '/' separator.
		{"*", "@scope/name", false},
		{"*", "express", true},
		// Scoped wildcard matches within the scope only.
		{"@scope/*", "@scope/name", true},
		{"@scope/*", "@scope/deep/name", false},
		// Exact scoped match.
		{"@scope/name", "@scope/name", true},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_vs_"+tt.name, func(t *testing.T) {
			policy := Policy{Exclusions: []string{tt.pattern}}
			if got := policy.IsExcluded(tt.name); got != tt.excluded {
				t.Errorf("Policy{Exclusions:[%q]}.IsExcluded(%q) = %v, want %v", tt.pattern, tt.name, got, tt.excluded)
			}
		})
	}
}

// TestPolicyIsExcluded_MalformedPattern verifies that a malformed glob (which
// makes path.Match return ErrBadPattern) is treated as "not excluded" rather
// than silently bypassing the age check. A bad exclusion entry must never cause
// a package to skip verification.
func TestPolicyIsExcluded_MalformedPattern(t *testing.T) {
	// "[" is an unterminated character class — path.Match returns ErrBadPattern.
	policy := Policy{Exclusions: []string{"["}}
	if policy.IsExcluded("express") {
		t.Error("malformed pattern should not exclude any package")
	}

	// A malformed pattern must not short-circuit a later valid match.
	policy = Policy{Exclusions: []string{"[", "express"}}
	if !policy.IsExcluded("express") {
		t.Error("valid pattern after a malformed one should still match")
	}
}

func TestFormatAge(t *testing.T) {
	tests := []struct {
		age      time.Duration
		expected string
	}{
		{2 * time.Hour, "2h"},
		{24 * time.Hour, "1d"},
		{36 * time.Hour, "1d12h"},
		{72 * time.Hour, "3d"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := formatAge(tt.age)
			if got != tt.expected {
				t.Errorf("formatAge(%v) = %q, want %q", tt.age, got, tt.expected)
			}
		})
	}
}

func TestViolationToFinding(t *testing.T) {
	v := Violation{
		Name:            "evil-pkg",
		Version:         "1.0.0",
		PublishTime:     time.Now().Add(-2 * time.Hour),
		Age:             2 * time.Hour,
		PolicyThreshold: 72 * time.Hour,
		Severity:        model.SeverityHigh,
	}

	f := ViolationToFinding(v, "package-lock.json")

	if f.ID != "SUPPLY_CHAIN_AGE/evil-pkg@1.0.0" {
		t.Errorf("unexpected ID: %s", f.ID)
	}
	if f.Type != model.FindingTypeSCA {
		t.Errorf("unexpected type: %s", f.Type)
	}
	if f.Severity != model.SeverityHigh {
		t.Errorf("unexpected severity: %s", f.Severity)
	}
	if f.Package != "evil-pkg" {
		t.Errorf("unexpected package: %s", f.Package)
	}
	if f.Version != "1.0.0" {
		t.Errorf("unexpected version: %s", f.Version)
	}
	if f.File != "package-lock.json" {
		t.Errorf("unexpected file: %s", f.File)
	}
	if f.FindingCategory != "SUPPLY_CHAIN_AGE" {
		t.Errorf("unexpected category: %s", f.FindingCategory)
	}
}
