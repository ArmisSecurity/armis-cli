package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
)

// TestRunSupplyChainStatusJSON_MinAgeHumanReadable guards #22: the JSON policy
// min_age must use the human-readable formatter ("3 days"), not Go's internal
// Duration.String() ("72h0m0s"). With no config present, status falls back to
// DefaultPolicy (72h), so the field must render as "3 days".
func TestRunSupplyChainStatusJSON_MinAgeHumanReadable(t *testing.T) {
	dir := chdirTemp(t) // empty dir → no config → DefaultPolicy (72h)

	out := captureStdout(t, func() {
		if err := runSupplyChainStatusJSON(dir); err != nil {
			t.Fatalf("runSupplyChainStatusJSON: %v", err)
		}
	})

	var parsed struct {
		Policy struct {
			MinAge string `json:"min_age"`
		} `json:"policy"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("unmarshal status JSON: %v\n%s", err, out)
	}
	if parsed.Policy.MinAge != "3 days" {
		t.Errorf("min_age = %q, want %q (not the raw Duration.String())", parsed.Policy.MinAge, "3 days")
	}
}

// TestRunSupplyChainStatusJSON_MinAgeNonDefault drives a non-default config
// through the JSON path so a branch other than "days" is exercised end-to-end,
// and pins the singular form ("1 hour", not "1 hours") in the serialized output.
func TestRunSupplyChainStatusJSON_MinAgeNonDefault(t *testing.T) {
	dir := chdirTemp(t)
	writeConfig(t, dir, "version: 1\nmin-age: 1h\n")

	out := captureStdout(t, func() {
		if err := runSupplyChainStatusJSON(dir); err != nil {
			t.Fatalf("runSupplyChainStatusJSON: %v", err)
		}
	})

	var parsed struct {
		Policy struct {
			MinAge string `json:"min_age"`
		} `json:"policy"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("unmarshal status JSON: %v\n%s", err, out)
	}
	if parsed.Policy.MinAge != "1 hour" {
		t.Errorf("min_age = %q, want %q (singular, human-readable)", parsed.Policy.MinAge, "1 hour")
	}
}

// captureStdout swaps os.Stdout for a pipe, runs fn, and returns what fn wrote.
// A goroutine drains the pipe so output larger than the buffer cannot deadlock.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()
	_ = w.Close()
	os.Stdout = orig
	return <-done
}

func TestCollapsePipVariants(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "no pip leaves the list untouched",
			in:   []string{"npm", "pnpm", "bun"},
			want: []string{"npm", "pnpm", "bun"},
		},
		{
			name: "bare pip only renders as plain pip",
			in:   []string{"npm", "pip"},
			want: []string{"npm", "pip"},
		},
		{
			name: "pip plus variants collapse to a single token with the extra count",
			in:   []string{"npm", "pip", "pip3", "pip3.11", "pip3.12"},
			want: []string{"npm", "pip (+3 variants)"},
		},
		{
			name: "a single versioned variant with no bare pip still collapses",
			in:   []string{"uv", "pip3.12"},
			want: []string{"uv", "pip"},
		},
		{
			name: "exactly one extra variant uses the singular noun",
			in:   []string{"pip", "pip3"},
			want: []string{"pip (+1 variant)"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := collapsePipVariants(tt.in)
			if !slices.Equal(got, tt.want) {
				t.Errorf("collapsePipVariants(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestSummarizePMs(t *testing.T) {
	t.Run("short lists render in full", func(t *testing.T) {
		got := summarizePMs([]string{"npm", "pnpm"})
		if got != "npm, pnpm" {
			t.Errorf("summarizePMs = %q, want %q", got, "npm, pnpm")
		}
	})

	t.Run("long lists truncate with a +N more tail", func(t *testing.T) {
		// 7 distinct managers (no pip) → show 4, then "+3 more".
		got := summarizePMs([]string{"npm", "pnpm", "bun", "yarn", "uv", "poetry", "pdm"})
		if !strings.HasSuffix(got, ", +3 more") {
			t.Errorf("summarizePMs = %q, want a '+3 more' suffix", got)
		}
		if strings.Count(got, ",") != 4 { // 4 names shown (3 commas) + the "+3 more" comma
			t.Errorf("summarizePMs = %q, expected exactly 4 names before the tail", got)
		}
	})

	t.Run("pip variants are collapsed before truncating", func(t *testing.T) {
		// 3 managers + a pile of pip variants must read as 4 tokens, not be
		// pushed into a "+N more" by the pip3.x noise.
		// pip + 4 variants (pip3, pip3.11, pip3.12, pip3.13) → "pip (+4 variants)".
		got := summarizePMs([]string{"npm", "pnpm", "uv", "pip", "pip3", "pip3.11", "pip3.12", "pip3.13"})
		want := "npm, pnpm, uv, pip (+4 variants)"
		if got != want {
			t.Errorf("summarizePMs = %q, want %q", got, want)
		}
	})
}

func TestComputeVerdict(t *testing.T) {
	t.Run("ARMIS_SUPPLY_CHAIN=off is disabled regardless of wrappers", func(t *testing.T) {
		t.Setenv("ARMIS_SUPPLY_CHAIN", "OFF") // case-insensitive, mirrors the wrap gate
		v := computeVerdict([]string{"npm", "pnpm"})
		if v.State != "disabled" {
			t.Errorf("State = %q, want disabled", v.State)
		}
		if !strings.Contains(v.Headline, "ARMIS_SUPPLY_CHAIN=off") {
			t.Errorf("Headline = %q, want it to name the override", v.Headline)
		}
	})

	t.Run("no wrappers is inactive and points at init", func(t *testing.T) {
		t.Setenv("ARMIS_SUPPLY_CHAIN", "")
		v := computeVerdict(nil)
		if v.State != "inactive" {
			t.Errorf("State = %q, want inactive", v.State)
		}
		if !strings.Contains(v.Headline, "supply-chain init") {
			t.Errorf("Headline = %q, want it to suggest init", v.Headline)
		}
		if v.WrappedCount != 0 {
			t.Errorf("WrappedCount = %d, want 0", v.WrappedCount)
		}
	})

	t.Run("wrappers present is protected with a collapsed count", func(t *testing.T) {
		t.Setenv("ARMIS_SUPPLY_CHAIN", "")
		// 3 managers + 3 pip-family names → 4 distinct managers (pip counts once).
		v := computeVerdict([]string{"npm", "pnpm", "uv", "pip", "pip3", "pip3.12"})
		if v.State != "protected" {
			t.Errorf("State = %q, want protected", v.State)
		}
		if v.WrappedCount != 4 {
			t.Errorf("WrappedCount = %d, want 4 (pip family counts once)", v.WrappedCount)
		}
		if !strings.HasPrefix(v.Headline, "Protected — 4 commands wrapped") {
			t.Errorf("Headline = %q, want it to lead with the collapsed count", v.Headline)
		}
	})
}
