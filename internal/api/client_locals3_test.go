package api

import (
	"testing"
)

// TestWithLocalS3Hosts verifies that WithLocalS3Hosts correctly adds host:port entries to the allowlist.
func TestWithLocalS3Hosts(t *testing.T) {
	tests := []struct {
		name     string
		hosts    []string
		expected []string
	}{
		{
			name:     "single host",
			hosts:    []string{"awsmock-dev:4566"},
			expected: []string{"awsmock-dev:4566"},
		},
		{
			name:     "multiple hosts",
			hosts:    []string{"awsmock-dev:4566", "awsmock-backup:4567"},
			expected: []string{"awsmock-dev:4566", "awsmock-backup:4567"},
		},
		{
			name:     "hosts with whitespace",
			hosts:    []string{" awsmock-dev:4566 ", "  awsmock-backup:4567"},
			expected: []string{"awsmock-dev:4566", "awsmock-backup:4567"},
		},
		{
			name:     "mixed case normalized to lowercase",
			hosts:    []string{"AwsMock-Dev:4566", "AwsMock-Backup:4567"},
			expected: []string{"awsmock-dev:4566", "awsmock-backup:4567"},
		},
		{
			name:     "empty strings filtered out",
			hosts:    []string{"awsmock-dev:4566", "", "  ", "awsmock-backup:4567"},
			expected: []string{"awsmock-dev:4566", "awsmock-backup:4567"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &Client{}
			opt := WithLocalS3Hosts(tt.hosts...)
			opt(client)

			if len(client.localS3Hosts) != len(tt.expected) {
				t.Errorf("expected %d hosts, got %d", len(tt.expected), len(client.localS3Hosts))
			}

			for i, expected := range tt.expected {
				if client.localS3Hosts[i] != expected {
					t.Errorf("host[%d]: expected %q, got %q", i, expected, client.localS3Hosts[i])
				}
			}
		})
	}
}

// TestValidatePresignedURL_LocalS3Hosts verifies that configured local S3 hosts bypass validation.
func TestValidatePresignedURL_LocalS3Hosts(t *testing.T) {
	tests := []struct {
		name       string
		localHosts []string
		url        string
		expectErr  bool
	}{
		{
			name:       "configured host allows http",
			localHosts: []string{"awsmock-dev:4566"},
			url:        "http://awsmock-dev:4566/bucket/key?signature=xyz",
			expectErr:  false,
		},
		{
			name:       "unconfigured host rejects http",
			localHosts: []string{"awsmock-dev:4566"},
			url:        "http://other-host:4566/bucket/key?signature=xyz",
			expectErr:  true,
		},
		{
			name:       "host mismatch on port",
			localHosts: []string{"awsmock-dev:4566"},
			url:        "http://awsmock-dev:4567/bucket/key?signature=xyz",
			expectErr:  true,
		},
		{
			name:       "case insensitive host matching",
			localHosts: []string{"awsmock-dev:4566"},
			url:        "http://AwsMock-Dev:4566/bucket/key?signature=xyz",
			expectErr:  false,
		},
		{
			name:       "multiple hosts - first matches",
			localHosts: []string{"awsmock-dev:4566", "awsmock-backup:4567"},
			url:        "http://awsmock-dev:4566/bucket/key?signature=xyz",
			expectErr:  false,
		},
		{
			name:       "multiple hosts - second matches",
			localHosts: []string{"awsmock-dev:4566", "awsmock-backup:4567"},
			url:        "http://awsmock-backup:4567/bucket/key?signature=xyz",
			expectErr:  false,
		},
		{
			name:       "subdomain mismatch blocked",
			localHosts: []string{"awsmock-dev:4566"},
			url:        "http://evil.awsmock-dev:4566/bucket/key?signature=xyz",
			expectErr:  true,
		},
		{
			name:       "empty allowlist falls through to normal validation",
			localHosts: []string{},
			url:        "http://awsmock-dev:4566/bucket/key?signature=xyz",
			expectErr:  true, // HTTPS required
		},
		{
			name:       "configured host with https bypasses localS3Hosts check",
			localHosts: []string{"awsmock-dev:4566"},
			url:        "https://awsmock-dev:4566/bucket/key?signature=xyz",
			expectErr:  true, // HTTPS URLs still go through amazonaws.com validation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &Client{}
			if len(tt.localHosts) > 0 {
				opt := WithLocalS3Hosts(tt.localHosts...)
				opt(client)
			}

			err := client.ValidatePresignedURL(tt.url)
			if tt.expectErr && err == nil {
				t.Errorf("expected error for URL %q, got nil", tt.url)
			}
			if !tt.expectErr && err != nil {
				t.Errorf("expected no error for URL %q, got: %v", tt.url, err)
			}
		})
	}
}

// TestValidatePresignedURL_SecurityCheck ensures HTTP is ONLY allowed for exact local host matches.
func TestValidatePresignedURL_SecurityCheck(t *testing.T) {
	tests := []struct {
		name       string
		localHosts []string
		url        string
		expectErr  bool
		reason     string
	}{
		{
			name:       "production URL never uses localS3Hosts even if configured",
			localHosts: []string{"awsmock-dev:4566"},
			url:        "https://bucket.s3.amazonaws.com/key?signature=xyz",
			expectErr:  false,
			reason:     "HTTPS production URL passes normal validation (localS3Hosts not checked)",
		},
		{
			name:       "http production URL rejected even with localS3Hosts configured",
			localHosts: []string{"awsmock-dev:4566"},
			url:        "http://bucket.s3.amazonaws.com/key?signature=xyz",
			expectErr:  true,
			reason:     "HTTP to real S3 must be rejected regardless of localS3Hosts",
		},
		{
			name:       "misconfigured env var doesn't leak to production",
			localHosts: []string{"production-s3.company.com:443"},
			url:        "http://production-s3.company.com:443/bucket/key",
			expectErr:  false, // Would allow HTTP! This is why we need production detection
			reason:     "SECURITY WARNING: HTTP allowed for configured host - relies on env var not being set in production",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &Client{}
			if len(tt.localHosts) > 0 {
				opt := WithLocalS3Hosts(tt.localHosts...)
				opt(client)
			}

			err := client.ValidatePresignedURL(tt.url)
			if tt.expectErr && err == nil {
				t.Errorf("[%s] expected error for URL %q, got nil", tt.reason, tt.url)
			}
			if !tt.expectErr && err != nil {
				t.Errorf("[%s] expected no error for URL %q, got: %v", tt.reason, tt.url, err)
			}
		})
	}
}

// TestValidatePresignedURL_Regression ensures existing behavior is unchanged when no local hosts configured.
func TestValidatePresignedURL_Regression(t *testing.T) {
	client := &Client{} // No local hosts configured

	tests := []struct {
		name      string
		url       string
		expectErr bool
	}{
		{
			name:      "valid AWS S3 URL accepted",
			url:       "https://bucket.s3.amazonaws.com/key?signature=xyz",
			expectErr: false,
		},
		{
			name:      "valid AWS S3 regional URL accepted",
			url:       "https://bucket.s3.us-west-2.amazonaws.com/key?signature=xyz",
			expectErr: false,
		},
		{
			name:      "http AWS URL rejected",
			url:       "http://bucket.s3.amazonaws.com/key?signature=xyz",
			expectErr: true,
		},
		{
			name:      "non-S3 host rejected",
			url:       "https://evil.com/key?signature=xyz",
			expectErr: true,
		},
		{
			name:      "localhost rejected by default",
			url:       "http://localhost:4566/bucket/key",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.ValidatePresignedURL(tt.url)
			if tt.expectErr && err == nil {
				t.Errorf("expected error for URL %q, got nil", tt.url)
			}
			if !tt.expectErr && err != nil {
				t.Errorf("expected no error for URL %q, got: %v", tt.url, err)
			}
		})
	}
}
