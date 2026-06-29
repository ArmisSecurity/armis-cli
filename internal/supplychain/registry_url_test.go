package supplychain

import (
	"strings"
	"testing"
)

// TestStripURLUserinfo is part of test-plan case #7 (credential-leak
// prevention): a userinfo-bearing origin must be stripped before it can be
// written into a lockfile as the residue rewrite target.
func TestStripURLUserinfo(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "user:pass stripped", in: "https://user:tok@nexus.corp/npm", want: "https://nexus.corp/npm"}, //nolint:gosec // G101: test fixture URL, not a real credential
		{name: "user only stripped", in: "https://user@nexus.corp/npm", want: "https://nexus.corp/npm"},
		{name: "no userinfo unchanged", in: "https://nexus.corp/npm", want: "https://nexus.corp/npm"},
		{name: "preserves port and path", in: "https://u:p@nexus.corp:8443/repository/npm", want: "https://nexus.corp:8443/repository/npm"}, //nolint:gosec // G101: test fixture URL, not a real credential
		{name: "malformed returned unchanged", in: "://bad", want: "://bad"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StripURLUserinfo(tt.in); got != tt.want {
				t.Errorf("StripURLUserinfo(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if strings.Contains(StripURLUserinfo(tt.in), "tok") {
				t.Errorf("token leaked through StripURLUserinfo(%q)", tt.in)
			}
		})
	}
}

// TestValidateRegistryURL is test-plan case #1 (P1, security). Each row pairs a
// positive (accepted) or negative (rejected) expectation; the negative cases
// ARE the SSRF security guarantee, so they are exhaustive over the threat
// ranges called out in the design's Security Requirements.
func TestValidateRegistryURL(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr bool
		errHas  string // substring the rejection message should contain
	}{
		// --- accepted ---
		{name: "https public host", raw: "https://nexus.corp/repository/npm-group/"},
		{name: "https with port", raw: "https://nexus.corp:8443/repository/npm/"},
		{name: "https private DNS name (internal registry)", raw: "https://artifactory.internal/npm/"},
		{name: "https public IP literal", raw: "https://8.8.8.8/npm/"},

		// --- rejected: scheme ---
		{name: "http scheme", raw: "http://nexus.corp/npm/", wantErr: true, errHas: "https"},
		{name: "file scheme", raw: "file:///etc/passwd", wantErr: true, errHas: "https"},
		{name: "empty", raw: "", wantErr: true},
		{name: "whitespace only", raw: "   ", wantErr: true},

		// --- rejected: embedded credentials (S3 / leak prevention) ---
		{name: "userinfo user:pass", raw: "https://user:token@nexus.corp/npm/", wantErr: true, errHas: "credentials"}, //nolint:gosec // G101: test fixture URL, not a real credential
		{name: "userinfo user only", raw: "https://user@nexus.corp/npm/", wantErr: true, errHas: "credentials"},

		// --- rejected: non-routable IPs (SSRF) ---
		{name: "loopback v4", raw: "https://127.0.0.1/npm/", wantErr: true, errHas: "loopback"},
		{name: "loopback v6", raw: "https://[::1]/npm/", wantErr: true, errHas: "loopback"},
		{name: "IMDS link-local", raw: "https://169.254.169.254/latest/meta-data/", wantErr: true, errHas: "link-local"},
		{name: "RFC1918 10/8", raw: "https://10.0.0.5/npm/", wantErr: true, errHas: "private"},
		{name: "RFC1918 172.16/12", raw: "https://172.16.0.1/npm/", wantErr: true, errHas: "private"},
		{name: "RFC1918 192.168/16", raw: "https://192.168.1.1/npm/", wantErr: true, errHas: "private"},
		{name: "IPv6 unique-local", raw: "https://[fc00::1]/npm/", wantErr: true, errHas: "private"},
		{name: "unspecified v4", raw: "https://0.0.0.0/npm/", wantErr: true, errHas: "unspecified"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := ValidateRegistryURL(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ValidateRegistryURL(%q) = nil error, want rejection", tt.raw)
				}
				if tt.errHas != "" && !strings.Contains(err.Error(), tt.errHas) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errHas)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateRegistryURL(%q) unexpected error: %v", tt.raw, err)
			}
			if u == nil {
				t.Fatalf("ValidateRegistryURL(%q) returned nil URL with no error", tt.raw)
			}
		})
	}
}
