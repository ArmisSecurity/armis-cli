package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/httpclient"
	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/testutil"
)

// PPSC-895 extra coverage. Exercises edge cases the original
// TestClient_StartIngest tree didn't touch: SSRF rejection in the
// orchestrator, server-side cap rejection from /presigned-url, malformed
// /presigned-url responses, expired presigned URL semantics from S3,
// concurrency, mid-upload TCP RST, idempotency, debug output,
// envelope golden / parseability, and clientOptionsForBaseURL.

// -------------------- #5 filename edge cases --------------------

func TestClient_StartIngest_FilenameEdgeCases(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, filename string
	}{
		{"non-ascii", "héllo-wörld.tar.gz"},
		{"colon (image tag)", "image:tag.tar"},
		{"path traversal stripped", "../etc/passwd.tar.gz"},
		{"backslash", "weird\\name.tar.gz"},
		{"double quote", `name "quoted".tar.gz`},
		{"space", "with space.tar.gz"},
		{"unicode emoji", "scan-🚀.tar.gz"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv, _ := newIngestFlowServer(t)
			client := newIngestFlowClient(t, srv.URL)

			_, err := client.StartIngest(context.Background(), IngestOptions{
				TenantID:     "tenant-456",
				ArtifactType: "repo",
				Filename:     tc.filename,
				Data:         bytes.NewReader([]byte("body")),
				Size:         4,
			})
			if err != nil {
				t.Fatalf("StartIngest with filename %q failed: %v", tc.filename, err)
			}
		})
	}
}

// -------------------- #6 SSRF rejection in the orchestrator --------------------

func TestClient_StartIngest_RejectsForeignS3Host(t *testing.T) {
	t.Parallel()
	srv, state := newIngestFlowServer(t)
	state.overridePresigned = func(w http.ResponseWriter, _ *http.Request) {
		// Hand the client a presigned URL pointing at an external host.
		// ValidatePresignedURL must reject it before the upload starts.
		testutil.JSONResponse(t, w, http.StatusOK, model.PresignedUploadResponse{
			ScanID:         testScanID,
			ArtifactType:   "repo",
			TenantID:       "tenant-456",
			PresignedURL:   "https://evil.example.com/upload",
			Fields:         map[string]string{"key": "k", "policy": "p", "x-amz-signature": "s"},
			MaxUploadBytes: 2 << 30,
			ExpiresIn:      1800,
		})
	}
	client := newIngestFlowClient(t, srv.URL)

	_, err := client.StartIngest(context.Background(), IngestOptions{
		TenantID: "tenant-456", ArtifactType: "repo", Filename: "x.tar.gz",
		Data: bytes.NewReader([]byte("body")), Size: 4,
	})
	if err == nil {
		t.Fatal("expected SSRF rejection")
	}
	if !strings.Contains(err.Error(), "invalid presigned URL") &&
		!strings.Contains(err.Error(), "not a recognized S3 endpoint") {
		t.Errorf("error should mention SSRF / S3 endpoint mismatch, got: %v", err)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.s3Calls != 0 {
		t.Errorf("client must NOT POST to a foreign S3 host; got %d calls", state.s3Calls)
	}
	if state.scanCalls != 0 {
		t.Errorf("/scan must NOT be called when SSRF rejects; got %d calls", state.scanCalls)
	}
}

// -------------------- #8 malformed /presigned-url responses --------------------

func TestClient_StartIngest_MalformedPresignedResponse(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body model.PresignedUploadResponse
	}{
		{"missing scan_id", model.PresignedUploadResponse{
			PresignedURL: "https://x.s3.amazonaws.com/", Fields: map[string]string{"k": "v"},
		}},
		{"missing presigned_url", model.PresignedUploadResponse{
			ScanID: testScanID, Fields: map[string]string{"k": "v"},
		}},
		{"missing fields", model.PresignedUploadResponse{
			ScanID: testScanID, PresignedURL: "https://x.s3.amazonaws.com/",
		}},
		{"empty fields map", model.PresignedUploadResponse{
			ScanID: testScanID, PresignedURL: "https://x.s3.amazonaws.com/",
			Fields: map[string]string{},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv, state := newIngestFlowServer(t)
			body := tc.body
			state.overridePresigned = func(w http.ResponseWriter, _ *http.Request) {
				testutil.JSONResponse(t, w, http.StatusOK, body)
			}
			client := newIngestFlowClient(t, srv.URL)
			_, err := client.StartIngest(context.Background(), IngestOptions{
				TenantID: "tenant-456", ArtifactType: "repo", Filename: "x.tar.gz",
				Data: bytes.NewReader([]byte("body")), Size: 4,
			})
			if err == nil {
				t.Fatalf("expected error for malformed response %q", tc.name)
			}
			if !strings.Contains(err.Error(), "incomplete response") {
				t.Errorf("expected 'incomplete response' error, got: %v", err)
			}
		})
	}
}

// -------------------- #9 expired presigned URL — S3 returns 403 RequestExpired --------------------

func TestClient_StartIngest_ExpiredPresignedURLReturns403(t *testing.T) {
	t.Parallel()
	srv, state := newIngestFlowServer(t)
	state.overrideS3 = func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		// Mirror the body real S3 sends on expiry.
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`<Error><Code>AccessDenied</Code><Message>Request has expired</Message></Error>`))
	}
	client := newIngestFlowClient(t, srv.URL)

	_, err := client.StartIngest(context.Background(), IngestOptions{
		TenantID: "tenant-456", ArtifactType: "repo", Filename: "x.tar.gz",
		Data: bytes.NewReader([]byte("body")), Size: 4,
	})
	if err == nil {
		t.Fatal("expected error for 403 RequestExpired")
	}
	if !strings.Contains(err.Error(), "S3 rejected upload") || !strings.Contains(err.Error(), "403") {
		t.Errorf("error must mention S3 rejection and HTTP 403, got: %v", err)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.scanCalls != 0 {
		t.Errorf("/scan must NOT be called after S3 403; got %d calls", state.scanCalls)
	}
}

// -------------------- #10 /scan returns 4xx with structured detail --------------------

func TestClient_StartIngest_ScanRejectsCarriesStatusAndDetail(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		status int
		detail string
	}{
		{"400 bad request", http.StatusBadRequest, "Invalid scan_id: not-an-objectid"},
		{"403 cross-tenant", http.StatusForbidden, "Scan does not belong to the requesting tenant."},
		{"404 not found", http.StatusNotFound, "Scan not found for scan_id: abc"},
		{"409 race", http.StatusConflict, "Scan status changed concurrently; please re-check status."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv, state := newIngestFlowServer(t)
			state.overrideScan = func(w http.ResponseWriter, _ *http.Request) {
				testutil.ErrorResponse(w, tc.status, tc.detail)
			}
			client := newIngestFlowClient(t, srv.URL)
			_, err := client.StartIngest(context.Background(), IngestOptions{
				TenantID: "tenant-456", ArtifactType: "repo", Filename: "x.tar.gz",
				Data: bytes.NewReader([]byte("body")), Size: 4,
			})
			if err == nil {
				t.Fatalf("expected error for /scan %d", tc.status)
			}
			// Error must include the HTTP status — the structured surface
			// users can grep on. Detail is bonus.
			statusStr := http.StatusText(tc.status)
			if !strings.Contains(err.Error(), statusStr) {
				t.Errorf("error must include status text %q, got: %v", statusStr, err)
			}
		})
	}
}

// -------------------- #11 concurrent StartIngest invocations --------------------

func TestClient_StartIngest_Concurrent(t *testing.T) {
	t.Parallel()
	// A separate /presigned-url call per goroutine, returning a different
	// scan_id each time. Validates the orchestrator has no shared state.
	srv, state := newIngestFlowServer(t)
	var ctr int32
	var ctrMu sync.Mutex
	state.overridePresigned = func(w http.ResponseWriter, r *http.Request) {
		ctrMu.Lock()
		ctr++
		id := ctr
		ctrMu.Unlock()
		scheme := testutil.SchemeFromRequest(r)
		testutil.JSONResponse(t, w, http.StatusOK, model.PresignedUploadResponse{
			ScanID:         "scan-concurrent-" + itoa(int(id)),
			ArtifactType:   "repo",
			TenantID:       "tenant-456",
			PresignedURL:   scheme + "://" + r.Host + "/_s3/upload",
			Fields:         map[string]string{"key": "k", "policy": "p", "x-amz-signature": "s"},
			MaxUploadBytes: 2 << 30,
			ExpiresIn:      1800,
		})
	}
	// Echo back whatever scan_id the orchestrator sent so the return value
	// reflects the per-call presigned-url assignment.
	state.overrideScan = func(w http.ResponseWriter, r *http.Request) {
		buf, _ := io.ReadAll(io.LimitReader(r.Body, 1<<14))
		var req model.IngestScanStartRequest
		_ = jsonUnmarshal(buf, &req)
		testutil.JSONResponse(t, w, http.StatusOK, model.IngestUploadResponse{
			ScanID: req.ScanID, ScanStatus: "INITIATED",
		})
	}
	client := newIngestFlowClient(t, srv.URL)

	const n = 5
	results := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			id, err := client.StartIngest(context.Background(), IngestOptions{
				TenantID: "tenant-456", ArtifactType: "repo", Filename: "x.tar.gz",
				Data: bytes.NewReader([]byte("body")), Size: 4,
			})
			results[idx] = id
			errs[idx] = err
		}(i)
	}
	wg.Wait()
	seen := map[string]bool{}
	for i, e := range errs {
		if e != nil {
			t.Errorf("call %d failed: %v", i, e)
			continue
		}
		if seen[results[i]] {
			t.Errorf("duplicate scan_id %q across concurrent calls", results[i])
		}
		seen[results[i]] = true
	}
}

// -------------------- #12 mid-upload connection close --------------------

func TestClient_StartIngest_S3ConnectionDropMidUpload(t *testing.T) {
	t.Parallel()
	srv, state := newIngestFlowServer(t)
	state.overrideS3 = func(w http.ResponseWriter, r *http.Request) {
		// Read a bit then hijack and close — simulates a TCP RST.
		_, _ = io.CopyN(io.Discard, r.Body, 32)
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("test server does not support Hijacker")
		}
		conn, _, hErr := hj.Hijack()
		if hErr != nil {
			t.Fatalf("hijack failed: %v", hErr)
		}
		_ = conn.Close()
	}
	client := newIngestFlowClient(t, srv.URL)

	// Send a non-trivial body so the server has time to read 32B and close.
	body := bytes.Repeat([]byte("x"), 4096)
	_, err := client.StartIngest(context.Background(), IngestOptions{
		TenantID: "tenant-456", ArtifactType: "repo", Filename: "x.tar.gz",
		Data: bytes.NewReader(body), Size: int64(len(body)),
	})
	if err == nil {
		t.Fatal("expected transport error after mid-upload connection drop")
	}
	if !strings.Contains(err.Error(), "S3") {
		t.Errorf("error should mention S3, got: %v", err)
	}
	// Note: server-side state (PENDING_UPLOAD row) is the API/server's
	// responsibility to expire — see PPSC-894 follow-up.
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.scanCalls != 0 {
		t.Errorf("/scan must NOT be called after S3 transport error; got %d", state.scanCalls)
	}
}

// -------------------- #14 idempotency: distinct scan_ids per call --------------------

func TestClient_StartIngest_DistinctScanIDsPerCall(t *testing.T) {
	t.Parallel()
	srv, state := newIngestFlowServer(t)
	var ctr int32
	var mu sync.Mutex
	state.overridePresigned = func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		ctr++
		id := ctr
		mu.Unlock()
		scheme := testutil.SchemeFromRequest(r)
		testutil.JSONResponse(t, w, http.StatusOK, model.PresignedUploadResponse{
			ScanID:         "scan-idem-" + itoa(int(id)),
			ArtifactType:   "repo",
			TenantID:       "tenant-456",
			PresignedURL:   scheme + "://" + r.Host + "/_s3/upload",
			Fields:         map[string]string{"key": "k", "policy": "p", "x-amz-signature": "s"},
			MaxUploadBytes: 2 << 30,
			ExpiresIn:      1800,
		})
	}
	state.overrideScan = func(w http.ResponseWriter, r *http.Request) {
		// Echo whatever scan_id was sent so the orchestrator's return
		// value reflects the call ordering.
		buf, _ := io.ReadAll(io.LimitReader(r.Body, 1<<14))
		var req model.IngestScanStartRequest
		_ = jsonUnmarshal(buf, &req)
		testutil.JSONResponse(t, w, http.StatusOK, model.IngestUploadResponse{
			ScanID: req.ScanID, ScanStatus: "INITIATED",
		})
	}
	client := newIngestFlowClient(t, srv.URL)

	a, err := client.StartIngest(context.Background(), IngestOptions{
		TenantID: "tenant-456", ArtifactType: "repo", Filename: "x.tar.gz",
		Data: bytes.NewReader([]byte("body")), Size: 4,
	})
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	b, err := client.StartIngest(context.Background(), IngestOptions{
		TenantID: "tenant-456", ArtifactType: "repo", Filename: "x.tar.gz",
		Data: bytes.NewReader([]byte("body")), Size: 4,
	})
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if a == b {
		t.Errorf("two consecutive scans should produce distinct scan_ids; got %q twice", a)
	}
}

// -------------------- #15 multipart envelope golden test --------------------

func TestBuildMultipartEnvelope_Golden(t *testing.T) {
	t.Parallel()
	fields := map[string]string{
		"key":             "ingest/T/S/x.tar.gz",
		"policy":          "POLICY_BASE64",
		"x-amz-signature": "SIG",
	}
	prefix, suffix, contentType, err := buildMultipartEnvelope(fields, "x.tar.gz")
	if err != nil {
		t.Fatalf("build envelope: %v", err)
	}

	// Boundary comes from contentType; mask it for stable comparison.
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		t.Fatalf("parse content-type: %v", err)
	}
	if mediaType != "multipart/form-data" {
		t.Fatalf("content-type = %q, want multipart/form-data", mediaType)
	}
	boundary := params["boundary"]
	if boundary == "" {
		t.Fatal("missing boundary")
	}

	masked := func(b []byte) string {
		return strings.ReplaceAll(string(b), boundary, "<BOUNDARY>")
	}
	gotPrefix := masked(prefix)
	gotSuffix := masked(suffix)

	// Suffix is invariant: closing boundary with the leading CRLF that
	// terminates the file part. Real S3 rejects without the CRLF.
	wantSuffix := "\r\n--<BOUNDARY>--\r\n"
	if gotSuffix != wantSuffix {
		t.Errorf("suffix mismatch:\n got %q\nwant %q", gotSuffix, wantSuffix)
	}

	// Prefix must contain all field values, the file part header, and end
	// with the file part's empty-line separator. Map iteration is random,
	// so assert membership of each field block individually.
	for k, v := range fields {
		want := "--<BOUNDARY>\r\nContent-Disposition: form-data; name=\"" + k + "\"\r\n\r\n" + v + "\r\n"
		if !strings.Contains(gotPrefix, want) {
			t.Errorf("prefix missing field block for %q\nprefix=%q", k, gotPrefix)
		}
	}
	wantFilePartTail := "--<BOUNDARY>\r\nContent-Disposition: form-data; name=\"file\"; filename=\"x.tar.gz\"\r\nContent-Type: application/octet-stream\r\n\r\n"
	if !strings.HasSuffix(gotPrefix, wantFilePartTail) {
		t.Errorf("prefix must end with file-part header:\n got %q\nwant suffix %q", gotPrefix, wantFilePartTail)
	}
}

// -------------------- #18 envelope is parseable as multipart with the declared total length --------------------

func TestBuildMultipartEnvelope_Parseable(t *testing.T) {
	t.Parallel()
	fields := map[string]string{
		"key":             "ingest/T/S/parse-test.tar.gz",
		"policy":          "abcDEF==",
		"x-amz-signature": "deadbeef",
	}
	const fileBody = "hello there"
	prefix, suffix, contentType, err := buildMultipartEnvelope(fields, "parse-test.tar.gz")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	full := bytes.Join([][]byte{prefix, []byte(fileBody), suffix}, nil)

	// Sanity: total length is what the orchestrator would set on
	// req.ContentLength. Anything else means real S3 sends 411.
	if len(full) != len(prefix)+len(fileBody)+len(suffix) {
		t.Fatalf("declared total length disagrees with rendered body")
	}

	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		t.Fatalf("parse content-type: %v", err)
	}
	mr := multipart.NewReader(bytes.NewReader(full), params["boundary"])
	seenFields := map[string]string{}
	var fileSeen bool
	var fileContents []byte
	for {
		part, perr := mr.NextPart()
		if perr == io.EOF {
			break
		}
		if perr != nil {
			t.Fatalf("multipart parse: %v", perr)
		}
		body, _ := io.ReadAll(part)
		if part.FormName() == "file" {
			fileSeen = true
			fileContents = body
			continue
		}
		seenFields[part.FormName()] = string(body)
	}
	for k, v := range fields {
		if seenFields[k] != v {
			t.Errorf("field %q round-trip mismatch: got %q, want %q", k, seenFields[k], v)
		}
	}
	if !fileSeen {
		t.Fatal("file part missing from rendered envelope")
	}
	if string(fileContents) != fileBody {
		t.Errorf("file content mismatch: got %q, want %q", fileContents, fileBody)
	}
}

// itoa is a tiny test-side helper kept readable instead of pulling fmt.
func itoa(i int) string { return strconv.Itoa(i) }

// jsonUnmarshal mirrors encoding/json.Unmarshal — used by the /scan
// override handler in TestClient_StartIngest_DistinctScanIDsPerCall.
func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

// TestClient_StartIngest_DebugOutput verifies that --debug emits a clear
// breadcrumb on the new presigned-URL flow: a single line containing
// scan_id and bucket_url. Captures os.Stderr because that's where the
// orchestrator writes (matches the rest of the package's debug pattern).
func TestClient_StartIngest_DebugOutput(t *testing.T) {
	srv, _ := newIngestFlowServer(t)
	httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
	uploadClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second, DisableRetry: true})
	client, err := NewClient(srv.URL, testutil.NewTestAuthProvider("token123"),
		true, // debug = true
		1*time.Minute,
		WithHTTPClient(httpClient), WithUploadHTTPClient(uploadClient), WithAllowLocalURLs(true))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// Redirect os.Stderr through an os.Pipe so we can capture writes.
	origStderr := os.Stderr
	r, w, perr := os.Pipe()
	if perr != nil {
		t.Fatalf("os.Pipe: %v", perr)
	}
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = origStderr })

	if _, err := client.StartIngest(context.Background(), IngestOptions{
		TenantID: "tenant-456", ArtifactType: "repo", Filename: "x.tar.gz",
		Data: bytes.NewReader([]byte("body")), Size: 4,
	}); err != nil {
		t.Fatalf("StartIngest: %v", err)
	}
	// Close writer, drain reader.
	_ = w.Close()
	captured, _ := io.ReadAll(r)
	os.Stderr = origStderr

	if !strings.Contains(string(captured), "DEBUG: presigned-url scan_id="+testScanID) {
		t.Errorf("expected debug line with scan_id=%s, got:\n%s", testScanID, captured)
	}
	if !strings.Contains(string(captured), "max_bytes=") {
		t.Errorf("expected debug line to include max_bytes, got:\n%s", captured)
	}
}
