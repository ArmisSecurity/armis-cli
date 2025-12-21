package cmd

import (
	"os"
	"testing"
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
				os.Setenv(tt.key, tt.envValue)
				defer os.Unsetenv(tt.key)
			} else {
				os.Unsetenv(tt.key)
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
				os.Setenv(tt.key, tt.envValue)
				defer os.Unsetenv(tt.key)
			} else {
				os.Unsetenv(tt.key)
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
}

func TestGetToken(t *testing.T) {
	t.Run("returns token when set", func(t *testing.T) {
		token = "test-token-123"
		defer func() { token = "" }()

		result, err := getToken()
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if result != "test-token-123" {
			t.Errorf("Expected 'test-token-123', got %s", result)
		}
	})

	t.Run("returns error when token not set", func(t *testing.T) {
		token = ""

		_, err := getToken()
		if err == nil {
			t.Error("Expected error when token not set")
		}
	})
}

func TestGetTenantID(t *testing.T) {
	t.Run("returns tenant ID when set", func(t *testing.T) {
		tenantID = "tenant-456"
		defer func() { tenantID = "" }()

		result, err := getTenantID()
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if result != "tenant-456" {
			t.Errorf("Expected 'tenant-456', got %s", result)
		}
	})

	t.Run("returns error when tenant ID not set", func(t *testing.T) {
		tenantID = ""

		_, err := getTenantID()
		if err == nil {
			t.Error("Expected error when tenant ID not set")
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

func TestExecute(t *testing.T) {
	err := Execute()
	if err != nil {
		t.Logf("Execute returned error (expected in test context): %v", err)
	}
}
