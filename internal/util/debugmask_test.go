package util

import (
	"strings"
	"testing"
)

func TestRedactPresignedURLCredentials(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		gone     []string
		kept     []string
		redacted int
	}{
		{
			// The shape the results API returns on dev (SigV2 with a session token).
			name:     "SigV2 with a session token",
			in:       "https://bucket.s3.amazonaws.com/ingest/t/s/results/x.json?AWSAccessKeyId=ASIAIOSFODNN7EXAMPLE&Signature=EXAMPLEsignature%3D&x-amz-security-token=EXAMPLEsessiontoken%2F%2F&Expires=1794561080",
			gone:     []string{"ASIAIOSFODNN7EXAMPLE", "EXAMPLEsignature", "EXAMPLEsessiontoken"},
			kept:     []string{"https://bucket.s3.amazonaws.com/ingest/t/s/results/x.json?", "Expires=1794561080"},
			redacted: 3,
		},
		{
			name:     "SigV4",
			in:       "https://b.s3.amazonaws.com/k?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIAIOSFODNN7EXAMPLE%2F20261113%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20261113T000000Z&X-Amz-Expires=900&X-Amz-SignedHeaders=host&X-Amz-Security-Token=EXAMPLEv4sessiontoken&X-Amz-Signature=EXAMPLEv4signature",
			gone:     []string{"ASIAIOSFODNN7EXAMPLE%2F20261113", "EXAMPLEv4sessiontoken", "EXAMPLEv4signature"},
			kept:     []string{"X-Amz-Algorithm=AWS4-HMAC-SHA256", "X-Amz-Expires=900", "X-Amz-SignedHeaders=host"},
			redacted: 3,
		},
		{
			// Go's encoding/json writes "&" as \u0026.
			name:     "inside JSON with an escaped ampersand",
			in:       `{"all_results":"https://b/k?AWSAccessKeyId=ASIAIOSFODNN7EXAMPLE\u0026Signature=EXAMPLEjsonsig%3D\u0026Expires=1"}`,
			gone:     []string{"ASIAIOSFODNN7EXAMPLE", "EXAMPLEjsonsig%3D"},
			kept:     []string{`\u0026Expires=1"}`},
			redacted: 2,
		},
		{
			// A presigned URL nested in another URL's query is encoded again.
			name:     "a nested URL with an encoded equals sign",
			in:       "https://app.example/open?to=https%3A%2F%2Fb%2Fk%3FAWSAccessKeyId%3DASIAIOSFODNN7EXAMPLE%26Signature%3DEXAMPLEnestedsig%26Expires%3D1",
			gone:     []string{"ASIAIOSFODNN7EXAMPLE", "EXAMPLEnestedsig"},
			kept:     []string{"https://app.example/open?to="},
			redacted: 1,
		},
		{
			// Percent-encoding is case-insensitive.
			name:     "a lowercase encoded equals sign",
			in:       "https://app.example/open?to=https%3a%2f%2fb%2fk%3fSignature%3dEXAMPLElowersig%26Expires%3d1",
			gone:     []string{"EXAMPLElowersig"},
			kept:     []string{"https://app.example/open?to="},
			redacted: 1,
		},
		{
			// One level deeper, "%" itself is encoded as "%25".
			name:     "a doubly nested URL",
			in:       "https://app.example/a?next=https%253A%252F%252Fb%252Fk%253FSignature%253DEXAMPLEdeepsig%2526Expires%253D1",
			gone:     []string{"EXAMPLEdeepsig"},
			kept:     []string{"https://app.example/a?next="},
			redacted: 1,
		},
		{
			name: "text without credentials is untouched",
			in:   "https://example.com/report?page=2&sort=desc",
			kept: []string{"https://example.com/report?page=2&sort=desc"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RedactPresignedURLCredentials(tt.in)
			for _, s := range tt.gone {
				if strings.Contains(got, s) {
					t.Errorf("%q survived redaction: %s", s, got)
				}
			}
			for _, s := range tt.kept {
				if !strings.Contains(got, s) {
					t.Errorf("%q should be kept: %s", s, got)
				}
			}
			if n := strings.Count(got, "REDACTED"); n != tt.redacted {
				t.Errorf("redacted %d parameters, want %d: %s", n, tt.redacted, got)
			}
		})
	}
}

func TestMaskForDebug(t *testing.T) {
	// An API body is one long line: past maxLineLength, line masking alone
	// would skip it entirely.
	long := strings.Repeat("x", maxLineLength)
	secret := "ghp_" + strings.Repeat("A", 36)
	body := `{"padding":"` + long + `","snippet":"token = '` + secret + `'","url":"https://b/k?Signature=abc123&Expires=1"}`

	got := MaskForDebug([]byte(body))

	if strings.Contains(got, secret) {
		t.Error("the secret in the snippet was not masked")
	}
	if strings.Contains(got, "abc123") || !strings.Contains(got, "Signature=REDACTED") {
		t.Errorf("the URL signature was not redacted:\n%.300s", got)
	}
	if !strings.Contains(got, "\n  \"snippet\"") {
		t.Errorf("JSON should be indented one field per line:\n%.300s", got)
	}

	// Not JSON: masked line by line, as is.
	if got := MaskForDebug([]byte("plain " + secret)); strings.Contains(got, secret) || !strings.HasPrefix(got, "plain ") {
		t.Errorf("plain text was not masked in place: %q", got)
	}
}
