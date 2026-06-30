package testutil

import "net/http"

// SchemeFromRequest returns "https" if the request was served over TLS,
// otherwise "http". Used by mock test handlers that need to reflect the
// httptest.Server's scheme back into a presigned URL they construct.
func SchemeFromRequest(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}
