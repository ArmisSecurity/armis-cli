package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/auth"
	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/testutil"
	"github.com/ArmisSecurity/armis-cli/internal/update"
)

// Test constants
const (
	testVersion = "1.0.0"
)

func TestSetVersion(t *testing.T) {
	SetVersion(testVersion, "abc123", "2024-01-01")

	if version != testVersion {
		t.Errorf("Expected version '1.0.0', got %s", version)
	}
	if commit != "abc123" {
		t.Errorf("Expected commit 'abc123', got %s", commit)
	}
	if date != "2024-01-01" {
		t.Errorf("Expected date '2024-01-01', got %s", date)
	}

	if rootCmd.Version != "1.0.0 (commit: abc123, built: 2024-01-01)" {
		t.Errorf("Unexpected rootCmd.Version: %s", rootCmd.Version)
	}
}

func TestGetEnvOrDefault(t *testing.T) {
	tests := []struct {
		name         string
		key          string
		defaultValue string
		envValue     string
		expected     string
	}{
		{
			name:         "returns env value when set",
			key:          "TEST_VAR",
			defaultValue: "default",
			envValue:     "from-env",
			expected:     "from-env",
		},
		{
			name:         "returns default when env not set",
			key:          "TEST_VAR_UNSET",
			defaultValue: "default",
			envValue:     "",
			expected:     "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				_ = os.Setenv(tt.key, tt.envValue)
				defer func() { _ = os.Unsetenv(tt.key) }()
			} else {
				_ = os.Unsetenv(tt.key)
			}

			result := getEnvOrDefault(tt.key, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("getEnvOrDefault() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestGetEnvOrDefaultInt(t *testing.T) {
	tests := []struct {
		name         string
		key          string
		defaultValue int
		envValue     string
		expected     int
	}{
		{
			name:         "returns env value when valid int",
			key:          "TEST_INT",
			defaultValue: 100,
			envValue:     "200",
			expected:     200,
		},
		{
			name:         "returns default when env not set",
			key:          "TEST_INT_UNSET",
			defaultValue: 100,
			envValue:     "",
			expected:     100,
		},
		{
			name:         "returns default when env is invalid int",
			key:          "TEST_INT_INVALID",
			defaultValue: 100,
			envValue:     "not-a-number",
			expected:     100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				_ = os.Setenv(tt.key, tt.envValue)
				defer func() { _ = os.Unsetenv(tt.key) }()
			} else {
				_ = os.Unsetenv(tt.key)
			}

			result := getEnvOrDefaultInt(tt.key, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("getEnvOrDefaultInt() = %d, want %d", result, tt.expected)
			}
		})
	}
}

func TestGetAPIBaseURL(t *testing.T) {
	const testRegion = "eu1"

	// Keep the test hermetic: a developer/CI ARMIS_API_URL export must not leak
	// into the dev/production/regional subtests, which expect the resolved URL.
	// The override-specific subtests below set ARMIS_API_URL explicitly.
	t.Setenv("ARMIS_API_URL", "")

	t.Run("returns dev URL when useDev is true", func(t *testing.T) {
		useDev = true
		defer func() { useDev = false }()

		result := getAPIBaseURL()
		if result != devBaseURL {
			t.Errorf("Expected dev URL %s, got %s", devBaseURL, result)
		}
	})

	t.Run("returns production URL when useDev is false", func(t *testing.T) {
		useDev = false

		result := getAPIBaseURL()
		if result != productionBaseURL {
			t.Errorf("Expected production URL %s, got %s", productionBaseURL, result)
		}
	})

	t.Run("returns ARMIS_API_URL override when set", func(t *testing.T) {
		useDev = false
		testURL := "http://localhost:8080"
		_ = os.Setenv("ARMIS_API_URL", testURL)
		defer func() { _ = os.Unsetenv("ARMIS_API_URL") }()

		result := getAPIBaseURL()
		if result != testURL {
			t.Errorf("Expected env override URL %s, got %s", testURL, result)
		}
	})

	t.Run("ARMIS_API_URL takes precedence over useDev", func(t *testing.T) {
		useDev = true
		testURL := "http://test-server:9090"
		_ = os.Setenv("ARMIS_API_URL", testURL)
		defer func() {
			_ = os.Unsetenv("ARMIS_API_URL")
			useDev = false
		}()

		result := getAPIBaseURL()
		if result != testURL {
			t.Errorf("Expected env override URL %s, got %s", testURL, result)
		}
	})

	t.Run("returns regional URL when region is set", func(t *testing.T) {
		useDev = false
		region = testRegion
		defer func() { region = "" }()

		result := getAPIBaseURL()
		want := "https://eu.moose.armis.com"
		if result != want {
			t.Errorf("Expected regional URL %s, got %s", want, result)
		}
	})

	t.Run("useDev takes precedence over region", func(t *testing.T) {
		useDev = true
		region = testRegion
		defer func() {
			useDev = false
			region = ""
		}()

		result := getAPIBaseURL()
		if result != devBaseURL {
			t.Errorf("Expected dev URL %s, got %s", devBaseURL, result)
		}
	})

	t.Run("ARMIS_API_URL takes precedence over region", func(t *testing.T) {
		useDev = false
		region = testRegion
		testURL := "http://test-server:9090"
		_ = os.Setenv("ARMIS_API_URL", testURL)
		defer func() {
			_ = os.Unsetenv("ARMIS_API_URL")
			region = ""
		}()

		result := getAPIBaseURL()
		if result != testURL {
			t.Errorf("Expected env override URL %s, got %s", testURL, result)
		}
	})
}

// newRegionAuthProvider builds a JWT AuthProvider whose token carries the given
// region claim, backed by a throwaway auth server. The cache dir is isolated via
// t.Setenv so region caching never touches the developer's real cache.
func newRegionAuthProvider(t *testing.T, tokenRegion string) *auth.AuthProvider {
	t.Helper()

	// Isolate the on-disk region cache to a temp dir for this test.
	switch runtime.GOOS {
	case "windows":
		t.Setenv("LocalAppData", t.TempDir())
	case "darwin":
		t.Setenv("HOME", t.TempDir())
	default:
		t.Setenv("XDG_CACHE_HOME", t.TempDir())
	}

	mockJWT := createMockJWTWithRegion("customer-123", time.Now().Add(time.Hour).Unix(), tokenRegion)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"token": mockJWT})
	}))
	t.Cleanup(server.Close)

	p, err := auth.NewAuthProvider(auth.AuthConfig{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		BaseURL:      server.URL,
	})
	if err != nil {
		t.Fatalf("NewAuthProvider failed: %v", err)
	}
	return p
}

func TestResolveDataPlaneURL(t *testing.T) {
	// Keep hermetic: a developer/CI ARMIS_API_URL export must not leak in.
	t.Setenv("ARMIS_API_URL", "")

	t.Run("auto-detects region from token when nothing is pinned", func(t *testing.T) {
		useDev = false
		region = ""
		p := newRegionAuthProvider(t, "eu1")

		got := resolveDataPlaneURL(context.Background(), p)
		want := "https://eu.moose.armis.com"
		if got != want {
			t.Errorf("Expected auto-detected URL %s, got %s", want, got)
		}
	})

	t.Run("falls back to production for us1 token (no dedicated data plane)", func(t *testing.T) {
		useDev = false
		region = ""
		p := newRegionAuthProvider(t, "us1")

		got := resolveDataPlaneURL(context.Background(), p)
		if got != productionBaseURL {
			t.Errorf("Expected production URL %s, got %s", productionBaseURL, got)
		}
	})

	t.Run("falls back to production when token has no region claim", func(t *testing.T) {
		useDev = false
		region = ""
		p := newRegionAuthProvider(t, "")

		got := resolveDataPlaneURL(context.Background(), p)
		if got != productionBaseURL {
			t.Errorf("Expected production URL %s, got %s", productionBaseURL, got)
		}
	})

	t.Run("explicit --region overrides token region", func(t *testing.T) {
		useDev = false
		region = "us1"
		defer func() { region = "" }()
		// Token says eu1, but the user pinned us1 explicitly: us1 wins.
		p := newRegionAuthProvider(t, "eu1")

		got := resolveDataPlaneURL(context.Background(), p)
		if got != productionBaseURL {
			t.Errorf("Expected explicit-region URL %s, got %s", productionBaseURL, got)
		}
	})

	t.Run("useDev overrides token region", func(t *testing.T) {
		useDev = true
		region = ""
		defer func() { useDev = false }()
		p := newRegionAuthProvider(t, "eu1")

		got := resolveDataPlaneURL(context.Background(), p)
		if got != devBaseURL {
			t.Errorf("Expected dev URL %s, got %s", devBaseURL, got)
		}
	})

	t.Run("ARMIS_API_URL overrides token region", func(t *testing.T) {
		useDev = false
		region = ""
		testURL := "http://localhost:8080"
		t.Setenv("ARMIS_API_URL", testURL)
		p := newRegionAuthProvider(t, "eu1")

		got := resolveDataPlaneURL(context.Background(), p)
		if got != testURL {
			t.Errorf("Expected env override URL %s, got %s", testURL, got)
		}
	})
}

func TestValidatePageLimit(t *testing.T) {
	tests := []struct {
		name    string
		limit   int
		wantErr bool
	}{
		{
			name:    "valid limit 1",
			limit:   1,
			wantErr: false,
		},
		{
			name:    "valid limit 500",
			limit:   500,
			wantErr: false,
		},
		{
			name:    "valid limit 1000",
			limit:   1000,
			wantErr: false,
		},
		{
			name:    "invalid limit 0",
			limit:   0,
			wantErr: true,
		},
		{
			name:    "invalid limit negative",
			limit:   -1,
			wantErr: true,
		},
		{
			name:    "invalid limit too large",
			limit:   1001,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePageLimit(tt.limit)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePageLimit(%d) error = %v, wantErr %v", tt.limit, err, tt.wantErr)
			}
		})
	}
}

func TestGetPageLimit(t *testing.T) {
	t.Run("returns valid page limit", func(t *testing.T) {
		pageLimit = 100
		defer func() { pageLimit = 500 }()

		result, err := getPageLimit()
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if result != 100 {
			t.Errorf("Expected 100, got %d", result)
		}
	})

	t.Run("returns error for invalid page limit", func(t *testing.T) {
		pageLimit = 2000
		defer func() { pageLimit = 500 }()

		_, err := getPageLimit()
		if err == nil {
			t.Error("Expected error for invalid page limit")
		}
	})
}

// Fail-on validation moved to internal/cmd/cmdutil (ValidateFailOn / GetFailOn);
// its unit tests live in cmdutil/failon_test.go. The supply-chain CI-gate
// regression that exercises the end-to-end path stays in supply_chain_test.go.

func TestExecute(t *testing.T) {
	err := Execute()
	if err != nil {
		t.Logf("Execute returned error (expected in test context): %v", err)
	}
}

func TestThemeFlag_Values(t *testing.T) {
	// Test that valid theme values are accepted by checking the flag exists
	flag := rootCmd.PersistentFlags().Lookup("theme")
	if flag == nil {
		t.Fatal("Expected --theme flag to be registered")
	}

	// Check default value
	if flag.DefValue != themeAuto {
		t.Errorf("Expected default value %q, got %q", themeAuto, flag.DefValue)
	}

	// Verify valid values are documented in usage
	usage := flag.Usage
	if usage == "" {
		t.Error("Expected --theme flag to have usage text")
	}
}

func TestThemeFlag_EnvDefault(t *testing.T) {
	// Save current value
	originalTheme := themeFlag

	// Test ARMIS_THEME env var is used for default
	_ = os.Setenv("ARMIS_THEME", "light")
	defer func() {
		_ = os.Unsetenv("ARMIS_THEME")
		themeFlag = originalTheme
	}()

	// The env var is read at init time, so we test getEnvOrDefault directly
	result := getEnvOrDefault("ARMIS_THEME", "auto")
	if result != "light" {
		t.Errorf("Expected 'light' from env, got %q", result)
	}
}

func TestThemeFlag_Validation(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		wantError bool
	}{
		{name: "valid auto", value: "auto", wantError: false},
		{name: "valid dark", value: "dark", wantError: false},
		{name: "valid light", value: "light", wantError: false},
		{name: "invalid value", value: "invalid", wantError: true},
		{name: "invalid empty", value: "", wantError: true},
		{name: "invalid typo", value: "drak", wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate theme value using the same logic as PersistentPreRunE
			var err error
			switch tt.value {
			case themeAuto, themeDark, themeLight:
				err = nil
			default:
				err = fmt.Errorf("invalid --theme value %q: must be auto, dark, or light", tt.value)
			}

			if (err != nil) != tt.wantError {
				t.Errorf("theme validation for %q: got error = %v, wantError = %v", tt.value, err, tt.wantError)
			}
		})
	}
}

func TestColorFlag_Validation(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		wantError bool
	}{
		{name: "valid auto", value: "auto", wantError: false},
		{name: "valid always", value: "always", wantError: false},
		{name: "valid never", value: "never", wantError: false},
		{name: "invalid value", value: "invalid", wantError: true},
		{name: "invalid typo", value: "allways", wantError: true},
		{name: "invalid empty", value: "", wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate color value using the same logic as PersistentPreRunE
			var err error
			mode := cli.ColorMode(tt.value)
			switch mode {
			case cli.ColorModeAuto, cli.ColorModeAlways, cli.ColorModeNever:
				err = nil
			default:
				err = fmt.Errorf("invalid --color value %q: must be auto, always, or never", tt.value)
			}
			if (err != nil) != tt.wantError {
				t.Errorf("color validation for %q: got error = %v, wantError = %v", tt.value, err, tt.wantError)
			}
		})
	}
}

// TestRootPersistentPreRunE tests the root command's PersistentPreRunE callback directly.
func TestRootPersistentPreRunE(t *testing.T) {
	// Save original values
	originalColorFlag := colorFlag
	originalThemeFlag := themeFlag
	originalVersion := version
	originalNoUpdateCheck := noUpdateCheck
	originalUpdateResultCh := updateResultCh

	t.Cleanup(func() {
		colorFlag = originalColorFlag
		themeFlag = originalThemeFlag
		version = originalVersion
		noUpdateCheck = originalNoUpdateCheck
		updateResultCh = originalUpdateResultCh
	})

	t.Run("valid color auto", func(t *testing.T) {
		colorFlag = testColorAuto
		themeFlag = themeAuto
		noUpdateCheck = true // Skip update check to simplify test

		err := rootCmd.PersistentPreRunE(rootCmd, []string{})
		if err != nil {
			t.Errorf("expected no error for valid color 'auto', got: %v", err)
		}
	})

	t.Run("valid color always", func(t *testing.T) {
		colorFlag = "always"
		themeFlag = themeAuto
		noUpdateCheck = true

		err := rootCmd.PersistentPreRunE(rootCmd, []string{})
		if err != nil {
			t.Errorf("expected no error for valid color 'always', got: %v", err)
		}
	})

	t.Run("valid color never", func(t *testing.T) {
		colorFlag = "never"
		themeFlag = themeAuto
		noUpdateCheck = true

		err := rootCmd.PersistentPreRunE(rootCmd, []string{})
		if err != nil {
			t.Errorf("expected no error for valid color 'never', got: %v", err)
		}
	})

	t.Run("invalid color returns error", func(t *testing.T) {
		colorFlag = testInvalidValue
		themeFlag = themeAuto
		noUpdateCheck = true

		err := rootCmd.PersistentPreRunE(rootCmd, []string{})
		if err == nil {
			t.Error("expected error for invalid color flag")
		}
		if err != nil && !testutil.ContainsSubstring(err.Error(), "invalid --color value") {
			t.Errorf("error message should contain 'invalid --color value', got: %v", err)
		}
	})

	t.Run("valid theme dark", func(t *testing.T) {
		colorFlag = testColorAuto
		themeFlag = "dark"
		noUpdateCheck = true

		err := rootCmd.PersistentPreRunE(rootCmd, []string{})
		if err != nil {
			t.Errorf("expected no error for valid theme 'dark', got: %v", err)
		}
	})

	t.Run("valid theme light", func(t *testing.T) {
		colorFlag = testColorAuto
		themeFlag = "light"
		noUpdateCheck = true

		err := rootCmd.PersistentPreRunE(rootCmd, []string{})
		if err != nil {
			t.Errorf("expected no error for valid theme 'light', got: %v", err)
		}
	})

	t.Run("invalid theme returns error", func(t *testing.T) {
		colorFlag = testColorAuto
		themeFlag = testInvalidValue
		noUpdateCheck = true

		err := rootCmd.PersistentPreRunE(rootCmd, []string{})
		if err == nil {
			t.Error("expected error for invalid theme flag")
		}
		if err != nil && !testutil.ContainsSubstring(err.Error(), "invalid --theme value") {
			t.Errorf("error message should contain 'invalid --theme value', got: %v", err)
		}
	})

	t.Run("skips update check in CI", func(t *testing.T) {
		colorFlag = testColorAuto
		themeFlag = themeAuto
		noUpdateCheck = false
		version = testVersion
		updateResultCh = nil

		// Set CI env var
		_ = os.Setenv("CI", "true")
		defer func() { _ = os.Unsetenv("CI") }()

		err := rootCmd.PersistentPreRunE(rootCmd, []string{})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		// In CI, updateResultCh should remain nil (no background check started)
		if updateResultCh != nil {
			t.Error("expected updateResultCh to remain nil in CI environment")
		}
	})

	t.Run("skips update check for dev version", func(t *testing.T) {
		colorFlag = testColorAuto
		themeFlag = themeAuto
		noUpdateCheck = false
		version = "dev"
		updateResultCh = nil

		// Ensure CI is not set
		_ = os.Unsetenv("CI")

		err := rootCmd.PersistentPreRunE(rootCmd, []string{})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		// For dev version, updateResultCh should remain nil
		if updateResultCh != nil {
			t.Error("expected updateResultCh to remain nil for dev version")
		}
	})
}

// TestPrintUpdateNotification tests the update notification printing.
func TestPrintUpdateNotification(t *testing.T) {
	// Helper to reset notification state for each test
	resetNotificationState := func() {
		updateNotificationMu.Lock()
		updateNotificationPrinted = false
		updateNotificationMu.Unlock()
		skipUpdateNotification = false
	}

	// Helper to clear CI environment variables and isolate cache directory.
	// This prevents tests from being affected by real cache files on disk.
	setupTestEnv := func(t *testing.T) {
		t.Helper()
		// Clear CI env vars
		ciVars := []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "TRAVIS", "CONTINUOUS_INTEGRATION"}
		for _, v := range ciVars {
			if val := os.Getenv(v); val != "" {
				_ = os.Unsetenv(v)
				t.Cleanup(func() { _ = os.Setenv(v, val) })
			}
		}
		// Isolate cache directory to prevent interference from real cache files
		tempDir := t.TempDir()
		if oldHome := os.Getenv("HOME"); oldHome != "" {
			_ = os.Setenv("HOME", tempDir)
			t.Cleanup(func() { _ = os.Setenv("HOME", oldHome) })
		}
		if oldXDG := os.Getenv("XDG_CACHE_HOME"); oldXDG != "" {
			_ = os.Setenv("XDG_CACHE_HOME", tempDir)
			t.Cleanup(func() { _ = os.Setenv("XDG_CACHE_HOME", oldXDG) })
		} else {
			_ = os.Setenv("XDG_CACHE_HOME", tempDir)
			t.Cleanup(func() { _ = os.Unsetenv("XDG_CACHE_HOME") })
		}
	}

	t.Run("nil channel does not panic", func(t *testing.T) {
		resetNotificationState()
		setupTestEnv(t)
		originalUpdateResultCh := updateResultCh
		originalVersion := version
		originalNoUpdateCheck := noUpdateCheck
		defer func() {
			updateResultCh = originalUpdateResultCh
			version = originalVersion
			noUpdateCheck = originalNoUpdateCheck
		}()

		// Set version to non-dev so skip conditions do not fire
		version = testVersion
		noUpdateCheck = false
		updateResultCh = nil

		// Should not panic
		PrintUpdateNotification()
	})

	t.Run("empty channel times out gracefully", func(t *testing.T) {
		resetNotificationState()
		setupTestEnv(t)
		originalUpdateResultCh := updateResultCh
		originalVersion := version
		originalNoUpdateCheck := noUpdateCheck
		defer func() {
			updateResultCh = originalUpdateResultCh
			version = originalVersion
			noUpdateCheck = originalNoUpdateCheck
		}()

		// Set version to non-dev so skip conditions do not fire
		version = testVersion
		noUpdateCheck = false

		// Create an unbuffered channel with no value
		updateResultCh = make(chan *update.CheckResult)

		// Should return after ~100ms timeout (not block indefinitely)
		done := make(chan bool, 1)
		go func() {
			PrintUpdateNotification()
			done <- true
		}()

		select {
		case <-done:
			// Success - function returned after timeout
		case <-time.After(200 * time.Millisecond):
			t.Error("PrintUpdateNotification blocked indefinitely on empty channel")
		}
	})

	t.Run("only prints once when called multiple times", func(t *testing.T) {
		resetNotificationState()
		setupTestEnv(t)
		originalUpdateResultCh := updateResultCh
		originalVersion := version
		originalNoUpdateCheck := noUpdateCheck
		defer func() {
			updateResultCh = originalUpdateResultCh
			version = originalVersion
			noUpdateCheck = originalNoUpdateCheck
		}()

		// Set version to non-dev so skip conditions don't fire
		version = testVersion
		noUpdateCheck = false

		// Create a buffered channel with a valid result that will trigger printing
		ch := make(chan *update.CheckResult, 1)
		ch <- &update.CheckResult{
			CurrentVersion: testVersion,
			LatestVersion:  "2.0.0",
		}
		close(ch)
		updateResultCh = ch

		// Call twice - should not panic or block, and should only print once
		PrintUpdateNotification()
		PrintUpdateNotification()

		// Verify flag is set (because we sent a valid result)
		updateNotificationMu.Lock()
		if !updateNotificationPrinted {
			t.Error("updateNotificationPrinted should be true after calling PrintUpdateNotification with valid result")
		}
		updateNotificationMu.Unlock()
	})

	t.Run("nil result does not set printed flag", func(t *testing.T) {
		resetNotificationState()
		setupTestEnv(t)
		originalUpdateResultCh := updateResultCh
		originalVersion := version
		originalNoUpdateCheck := noUpdateCheck
		defer func() {
			updateResultCh = originalUpdateResultCh
			version = originalVersion
			noUpdateCheck = originalNoUpdateCheck
		}()

		// Set version to non-dev so skip conditions don't fire
		version = testVersion
		noUpdateCheck = false

		// Create a buffered channel with nil result (no update available)
		ch := make(chan *update.CheckResult, 1)
		ch <- nil
		close(ch)
		updateResultCh = ch

		PrintUpdateNotification()

		// Verify flag is NOT set (nil result means nothing to print)
		updateNotificationMu.Lock()
		if updateNotificationPrinted {
			t.Error("updateNotificationPrinted should be false when no update is available")
		}
		updateNotificationMu.Unlock()
	})
}

// TestFlagErrorFunc_AppendsHelpHint verifies the FlagErrorFunc registered on
// rootCmd appends a "--help" hint using the full command path (not just the leaf
// name) so users get an actionable next step despite SilenceUsage.
func TestFlagErrorFunc_AppendsHelpHint(t *testing.T) {
	fn := rootCmd.FlagErrorFunc()
	if fn == nil {
		t.Fatal("expected a FlagErrorFunc to be registered on rootCmd")
	}

	// scanRepoCmd is a nested subcommand; its full path is "armis-cli scan repo".
	err := fn(scanRepoCmd, fmt.Errorf("unknown flag: --bogus-flag"))
	if err == nil {
		t.Fatal("expected FlagErrorFunc to return an error")
	}
	msg := err.Error()
	if !testutil.ContainsSubstring(msg, "unknown flag: --bogus-flag") {
		t.Errorf("expected original flag error preserved, got: %s", msg)
	}
	if !testutil.ContainsSubstring(msg, "armis-cli scan repo --help") {
		t.Errorf("expected full-path help hint 'armis-cli scan repo --help', got: %s", msg)
	}
}

// TestGetAuthProvider_NoCredentials tests auth provider creation with no credentials.
func TestGetAuthProvider_NoCredentials(t *testing.T) {
	// Save original values
	originalClientID := clientID
	originalClientSecret := clientSecret
	originalToken := token
	originalTenantID := tenantID

	t.Cleanup(func() {
		clientID = originalClientID
		clientSecret = originalClientSecret
		token = originalToken
		tenantID = originalTenantID
	})

	// Clear all auth credentials
	clientID = ""
	clientSecret = ""
	token = ""
	tenantID = ""

	_, err := getAuthProvider(context.Background())
	if err == nil {
		t.Error("expected error when no credentials are provided")
	}
}

// TestClientOptionsForBaseURL guards a production-config invariant: the new
// presigned-URL flow's SSRF allowlist (api.ValidatePresignedURL) is only
// relaxed via WithAllowLocalURLs(true), and that option must ONLY be
// returned for localhost-bound base URLs. A regression here would
// silently weaken production SSRF protection.
func TestClientOptionsForBaseURL(t *testing.T) {
	cases := []struct {
		name    string
		baseURL string
		want    bool // true = expect WithAllowLocalURLs(true) in result
	}{
		{"localhost http", "http://localhost:8080", true},
		{"localhost https", "https://localhost:8443", true},
		{"127.0.0.1", "http://127.0.0.1:8001", true},
		{"prod https", "https://api.armis.com", false},
		{"dev https", "https://moose-dev.armis.com", false},
		{"stg https", "https://moose-stg.armis.com", false},
		{"empty", "", false},
		{"unparseable", "://nope", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := clientOptionsForBaseURL(tc.baseURL)
			has := len(got) > 0
			if has != tc.want {
				t.Errorf("clientOptionsForBaseURL(%q) returned %d options (has=%v), want has=%v",
					tc.baseURL, len(got), has, tc.want)
			}
		})
	}
}
