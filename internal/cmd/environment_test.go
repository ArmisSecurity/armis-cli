package cmd

import (
	"os"
	"testing"
)

func TestIsLocalDevelopment(t *testing.T) {
	tests := []struct {
		name     string
		baseURL  string
		expected bool
	}{
		// Local development (should return true)
		{
			name:     "localhost",
			baseURL:  "http://localhost:8080",
			expected: true,
		},
		{
			name:     "localhost https",
			baseURL:  "https://localhost:8443",
			expected: true,
		},
		{
			name:     "loopback IP",
			baseURL:  "http://127.0.0.1:8080",
			expected: true,
		},
		{
			name:     "private IP 192.168",
			baseURL:  "http://192.168.1.100:8080",
			expected: true,
		},
		{
			name:     "private IP 10.x",
			baseURL:  "http://10.0.0.1:8080",
			expected: true,
		},
		{
			name:     "private IP 172.16",
			baseURL:  "http://172.16.0.1:8080",
			expected: true,
		},
		{
			name:     "private IP 172.31 (upper bound)",
			baseURL:  "http://172.31.255.255:8080",
			expected: true,
		},
		{
			name:     "case insensitive localhost",
			baseURL:  "http://LOCALHOST:8080",
			expected: true,
		},

		// Remote/Cloud (should return false)
		{
			name:     "production domain",
			baseURL:  "https://moose.armis.com",
			expected: false,
		},
		{
			name:     "EU production domain",
			baseURL:  "https://eu.moose.armis.com",
			expected: false,
		},
		{
			name:     "development domain",
			baseURL:  "https://moose-dev.armis.com",
			expected: false,
		},
		{
			name:     "staging domain",
			baseURL:  "https://moose-stg.armis.com",
			expected: false,
		},
		{
			name:     "external domain",
			baseURL:  "https://api.example.com",
			expected: false,
		},
		{
			name:     "public IP",
			baseURL:  "http://203.0.113.1:8080",
			expected: false,
		},
		{
			name:     "private IP 172.32 (out of range)",
			baseURL:  "http://172.32.0.1:8080",
			expected: false,
		},
		{
			name:     "private IP 172.15 (out of range)",
			baseURL:  "http://172.15.0.1:8080",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isLocalDevelopment(tt.baseURL)
			if got != tt.expected {
				t.Errorf("isLocalDevelopment(%q) = %v, want %v", tt.baseURL, got, tt.expected)
			}
		})
	}
}

func TestClientOptionsForBaseURL_LocalCheck(t *testing.T) {
	tests := []struct {
		name                 string
		baseURL              string
		localS3Endpoint      string
		expectLocalS3Enabled bool
	}{
		{
			name:                 "localhost allows local S3",
			baseURL:              "http://localhost:8080",
			localS3Endpoint:      "awsmock-dev:4566",
			expectLocalS3Enabled: true,
		},
		{
			name:                 "private IP allows local S3",
			baseURL:              "http://192.168.1.100:8080",
			localS3Endpoint:      "awsmock-dev:4566",
			expectLocalS3Enabled: true,
		},
		{
			name:                 "remote domain blocks local S3",
			baseURL:              "https://moose.armis.com",
			localS3Endpoint:      "awsmock-dev:4566",
			expectLocalS3Enabled: false,
		},
		{
			name:                 "dev domain blocks local S3",
			baseURL:              "https://moose-dev.armis.com",
			localS3Endpoint:      "awsmock-dev:4566",
			expectLocalS3Enabled: false,
		},
		{
			name:                 "no endpoint set - no options",
			baseURL:              "http://localhost:8080",
			localS3Endpoint:      "",
			expectLocalS3Enabled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set or clear env var
			if tt.localS3Endpoint != "" {
				os.Setenv("ARMIS_LOCAL_S3_ENDPOINT", tt.localS3Endpoint)
			} else {
				os.Unsetenv("ARMIS_LOCAL_S3_ENDPOINT")
			}
			defer os.Unsetenv("ARMIS_LOCAL_S3_ENDPOINT")

			opts := clientOptionsForBaseURL(tt.baseURL)

			if tt.expectLocalS3Enabled {
				if len(opts) == 0 {
					t.Errorf("Expected local S3 options to be enabled for %s, but got no options", tt.baseURL)
				}
			} else {
				if len(opts) > 0 && tt.localS3Endpoint != "" {
					t.Errorf("Expected local S3 options to be blocked for %s, but got %d options", tt.baseURL, len(opts))
				}
			}
		})
	}
}
