package image

import (
	"strings"
	"testing"
)

func TestValidateImageName(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid simple image",
			input:   "alpine",
			wantErr: false,
		},
		{
			name:    "valid image with tag",
			input:   "ubuntu:22.04",
			wantErr: false,
		},
		{
			name:    "valid image with registry and tag",
			input:   "docker.io/library/nginx:latest",
			wantErr: false,
		},
		{
			name:    "valid image with namespace",
			input:   "library/busybox",
			wantErr: false,
		},
		{
			name:      "image name with space",
			input:     "bad image",
			wantErr:   true,
			errSubstr: "whitespace",
		},
		{
			name:      "image name starting with dash",
			input:     "-malicious",
			wantErr:   true,
			errSubstr: "may not start with '-'",
		},
		{
			name:      "image name with option injection attempt",
			input:     "--config=/tmp/evil",
			wantErr:   true,
			errSubstr: "may not start with '-'",
		},
		{
			name:      "image name with newline",
			input:     "alpine\n",
			wantErr:   true,
			errSubstr: "whitespace/control",
		},
		{
			name:      "image name with tab",
			input:     "alpine\tmalicious",
			wantErr:   true,
			errSubstr: "whitespace/control",
		},
		{
			name:      "image name with semicolon command injection attempt",
			input:     "alpine; rm -rf /",
			wantErr:   true,
			errSubstr: "whitespace",
		},
		{
			name:      "empty image name",
			input:     "",
			wantErr:   true,
			errSubstr: "invalid",
		},
		{
			name:      "image name with pipe",
			input:     "alpine | malicious",
			wantErr:   true,
			errSubstr: "whitespace",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := validateImageName(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("validateImageName(%q) expected error containing %q, got nil", tt.input, tt.errSubstr)
				} else if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("validateImageName(%q) expected error containing %q, got %q", tt.input, tt.errSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("validateImageName(%q) unexpected error: %v", tt.input, err)
				}
				if result == "" {
					t.Errorf("validateImageName(%q) returned empty result", tt.input)
				}
			}
		})
	}
}

func TestValidateImageNameNormalization(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "adds latest tag when missing",
			input:    "alpine",
			expected: "alpine:latest",
		},
		{
			name:     "preserves explicit tag",
			input:    "ubuntu:22.04",
			expected: "ubuntu:22.04",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := validateImageName(tt.input)
			if err != nil {
				t.Errorf("validateImageName(%q) unexpected error: %v", tt.input, err)
			}
			if result != tt.expected {
				t.Errorf("validateImageName(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
