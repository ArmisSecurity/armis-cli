package cmd

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/update"
)

func TestSetVersion(t *testing.T) {
	SetVersion("1.0.0", "abc123", "2024-01-01")

	if version != "1.0.0" {
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

func TestValidateFailOn(t *testing.T) {
	tests := []struct {
		name       string
		severities []string
		wantErr    bool
	}{
		{
			name:       "valid single severity",
			severities: []string{"CRITICAL"},
			wantErr:    false,
		},
		{
			name:       "valid multiple severities",
			severities: []string{"HIGH", "CRITICAL"},
			wantErr:    false,
		},
		{
			name:       "valid all severities",
			severities: []string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"},
			wantErr:    false,
		},
		{
			name:       "valid severity lowercase",
			severities: []string{"high"},
			wantErr:    false,
		},
		{
			name:       "invalid severity unknown",
			severities: []string{"INVALID"},
			wantErr:    true,
		},
		{
			name:       "invalid mixed valid and invalid",
			severities: []string{"HIGH", "invalid"},
			wantErr:    true,
		},
		{
			name:       "empty slice is valid",
			severities: []string{},
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFailOn(tt.severities)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateFailOn(%v) error = %v, wantErr %v", tt.severities, err, tt.wantErr)
			}
		})
	}
}

func TestGetFailOn(t *testing.T) {
	t.Run("returns valid severities", func(t *testing.T) {
		failOn = []string{"HIGH", "CRITICAL"}
		defer func() { failOn = []string{"CRITICAL"} }()

		result, err := getFailOn()
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if len(result) != 2 || result[0] != "HIGH" || result[1] != "CRITICAL" {
			t.Errorf("Expected [HIGH CRITICAL], got %v", result)
		}
	})

	t.Run("returns error for invalid severity", func(t *testing.T) {
		failOn = []string{"invalid"}
		defer func() { failOn = []string{"CRITICAL"} }()

		_, err := getFailOn()
		if err == nil {
			t.Error("Expected error for invalid severity")
		}
	})
}

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
		if err != nil && !contains(err.Error(), "invalid --color value") {
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
		if err != nil && !contains(err.Error(), "invalid --theme value") {
			t.Errorf("error message should contain 'invalid --theme value', got: %v", err)
		}
	})

	t.Run("skips update check in CI", func(t *testing.T) {
		colorFlag = testColorAuto
		themeFlag = themeAuto
		noUpdateCheck = false
		version = "1.0.0"
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
	t.Run("nil channel does not panic", func(t *testing.T) {
		originalUpdateResultCh := updateResultCh
		defer func() { updateResultCh = originalUpdateResultCh }()

		updateResultCh = nil

		// Should not panic
		PrintUpdateNotification()
	})

	t.Run("empty channel does not block", func(t *testing.T) {
		originalUpdateResultCh := updateResultCh
		defer func() { updateResultCh = originalUpdateResultCh }()

		// Create an unbuffered channel with no value
		updateResultCh = make(chan *update.CheckResult)

		// Should return immediately without blocking
		done := make(chan bool, 1)
		go func() {
			PrintUpdateNotification()
			done <- true
		}()

		select {
		case <-done:
			// Success - function returned
		case <-time.After(100 * time.Millisecond):
			t.Error("PrintUpdateNotification blocked on empty channel")
		}
	})
}

// TestGetAuthProvider_NoCredentials tests auth provider creation with no credentials.
func TestGetAuthProvider_NoCredentials(t *testing.T) {
	// Save original values
	originalClientID := clientID
	originalClientSecret := clientSecret
	originalAuthEndpoint := authEndpoint
	originalToken := token
	originalTenantID := tenantID

	t.Cleanup(func() {
		clientID = originalClientID
		clientSecret = originalClientSecret
		authEndpoint = originalAuthEndpoint
		token = originalToken
		tenantID = originalTenantID
	})

	// Clear all auth credentials
	clientID = ""
	clientSecret = ""
	authEndpoint = ""
	token = ""
	tenantID = ""

	_, err := getAuthProvider()
	if err == nil {
		t.Error("expected error when no credentials are provided")
	}
}

// contains is a helper for checking if a string contains a substring.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
