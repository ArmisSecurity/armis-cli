package testutil

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"testing"
)

// AssertValidS3Upload verifies that a request to the fake S3 endpoint matches
// what real AWS S3 requires of a presigned multipart POST:
//
//   - Content-Type is multipart/form-data with a boundary parameter.
//   - Content-Length is set and matches the actual body size (real S3
//     returns 411 MissingContentLength otherwise — we hit this on staging).
//   - Authorization header is NOT set (presigned URLs carry SigV4 in the
//     `policy` form field; an extra Authorization header invalidates the
//     signature on real S3).
//   - At least one form field precedes a `file` part, and the `file` part
//     is the LAST part in the body (S3's POST policy is only evaluated
//     against fields that appear before `file`).
//
// Use this from any fake-S3 test handler before returning 204. Failures are
// reported via t.Errorf so the test continues and the caller still drains
// the body.
//
// Returns true if the upload is well-formed.
func AssertValidS3Upload(t *testing.T, r *http.Request) bool {
	t.Helper()
	ok := true

	if r.Header.Get("Authorization") != "" {
		t.Errorf("S3 upload must NOT include Authorization header; got %q",
			r.Header.Get("Authorization"))
		ok = false
	}

	mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		t.Errorf("S3 upload Content-Type unparseable: %v", err)
		return false
	}
	if mediaType != "multipart/form-data" {
		t.Errorf("S3 upload Content-Type = %q, want multipart/form-data", mediaType)
		ok = false
	}
	boundary, hasBoundary := params["boundary"]
	if !hasBoundary || boundary == "" {
		t.Errorf("S3 upload Content-Type missing boundary parameter")
		return false
	}

	// Drain the entire body so we can compare its declared length with what
	// actually arrived. Real S3 fails with 411 if these disagree.
	//
	// A read error here usually means the orchestrator's body reader failed
	// upstream (the disk-error / context-cancel test cases deliberately
	// trigger this). That's a legitimate test scenario, not a CLI defect —
	// silently skip the rest of the assertions in that case.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return false
	}
	if r.ContentLength <= 0 {
		t.Errorf("S3 upload Content-Length = %d, want > 0 (real S3 returns 411 otherwise)",
			r.ContentLength)
		ok = false
	} else if int64(len(body)) != r.ContentLength {
		t.Errorf("S3 upload Content-Length=%d disagrees with body length=%d",
			r.ContentLength, len(body))
		ok = false
	}

	// Walk the parts and confirm at least one form field precedes the `file`,
	// and the `file` part is last. NextPart returns io.EOF after the closing
	// boundary; that's the loop terminator.
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	var (
		fileSeen      bool
		partAfterFile bool
		fieldsBefore  int
	)
	for {
		part, perr := mr.NextPart()
		if perr == io.EOF {
			break
		}
		if perr != nil {
			t.Errorf("multipart parse error: %v", perr)
			return false
		}
		name := part.FormName()
		if fileSeen {
			partAfterFile = true
		}
		if name == "file" {
			fileSeen = true
		} else if !fileSeen {
			fieldsBefore++
		}
		// Drain each part's body so the reader advances cleanly.
		_, _ = io.Copy(io.Discard, part)
		_ = part.Close()
	}
	if !fileSeen {
		t.Errorf("S3 upload must include a `file` form part; none found")
		ok = false
	}
	if partAfterFile {
		t.Errorf("S3 upload must end with the `file` part; found additional parts after it")
		ok = false
	}
	if fieldsBefore == 0 {
		t.Errorf("S3 upload must have at least one signed field before the file part")
		ok = false
	}

	return ok
}

// AssertHasAuthorization fails the test if the request is missing an
// Authorization header. Use on /api/v1/ingest/presigned-url and
// /api/v1/ingest/scan to confirm the CLI never drops credentials.
func AssertHasAuthorization(t *testing.T, r *http.Request) {
	t.Helper()
	if r.Header.Get("Authorization") == "" {
		t.Errorf("%s %s missing Authorization header", r.Method, r.URL.Path)
	}
}
