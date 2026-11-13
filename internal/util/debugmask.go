package util

import (
	"bytes"
	"encoding/json"
	"regexp"
)

// presignedURLCredential matches the credential parameters of a presigned URL
// query string, SigV2 and SigV4 alike: the access key id, the signature and the
// session token. Whoever reads them can fetch the object until the URL expires.
// The value stops at '&', a quote, whitespace or a backslash (JSON escapes "&"
// as \u0026), so the rest of the URL stays readable. There is no word
// boundary before the name: after \u0026 there is none. A URL nested in
// another URL's query is encoded again, so "=" may also appear as "%3D", or
// "%253D" one level deeper (any case: the pattern is case-insensitive); its
// value then runs on past the encoded "&" (%26), which only over-redacts.
var presignedURLCredential = regexp.MustCompile(`(?i)(AWSAccessKeyId|Signature|X-Amz-Credential|X-Amz-Signature|X-Amz-Security-Token)(=|%(?:25)*3D)[^&"'\s\\]+`)

// RedactPresignedURLCredentials replaces the credential parameters of every
// presigned URL in s with REDACTED.
func RedactPresignedURLCredentials(s string) string {
	return presignedURLCredential.ReplaceAllString(s, "${1}${2}REDACTED")
}

// MaskForDebug prepares a raw API body for a --debug dump, which may be shared
// or land in a CI log: presigned URL credentials are redacted, and secrets are
// masked as in regular output. JSON is indented first, one field per line,
// because secret masking skips lines longer than maxLineLength and an API body
// is usually a single long line.
func MaskForDebug(body []byte) string {
	redacted := []byte(RedactPresignedURLCredentials(string(body)))
	var indented bytes.Buffer
	if json.Valid(redacted) && json.Indent(&indented, redacted, "", "  ") == nil {
		redacted = indented.Bytes()
	}
	return MaskSecretInMultiLineString(string(redacted))
}
