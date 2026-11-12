package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

// projectsPath is the AppSec projects collection, relative to the base URL.
const projectsPath = "/api/v1/appsec/projects"

// AppSec error codes the CLI branches on (the API's `error` field).
const (
	// AppSecCodeProjectNameConflict: a project with that exact name exists;
	// context.conflicting_project_id names it.
	AppSecCodeProjectNameConflict = "project_name_conflict"
	// AppSecCodeInsufficientRole: the caller's role may not use the endpoint.
	AppSecCodeInsufficientRole = "insufficient_role"
)

// maxErrorDetailLen bounds how much of an unparseable error body is kept.
const maxErrorDetailLen = 512

// MaxProjectListLimit is the largest page GET /api/v1/appsec/projects serves.
const MaxProjectListLimit = 200

// AppSecError is a non-2xx response from the AppSec API (/api/v1/appsec/...).
// Domain and guard errors carry a machine-readable Code and Context; platform
// errors (a 401, or the 404 returned when AppSec is off for the tenant) carry
// only Detail.
type AppSecError struct {
	StatusCode int
	Code       string
	Detail     string
	Context    map[string]any
}

// Error renders the status, code and detail.
func (e *AppSecError) Error() string {
	detail := e.Detail
	if detail == "" {
		detail = http.StatusText(e.StatusCode)
	}
	if e.Code != "" {
		return fmt.Sprintf("AppSec API returned %d (%s): %s", e.StatusCode, e.Code, detail)
	}
	return fmt.Sprintf("AppSec API returned %d: %s", e.StatusCode, detail)
}

// ContextString returns Context[key] when it is a string, or "".
func (e *AppSecError) ContextString(key string) string {
	if v, ok := e.Context[key].(string); ok {
		return v
	}
	return ""
}

// ProjectListOptions filters GET /api/v1/appsec/projects.
type ProjectListOptions struct {
	// Query is `q`: a case-insensitive substring of a project's name,
	// repository or tags. The API has no exact-name filter.
	Query string
	// Statuses is the repeatable `status` filter; empty means the API default
	// (active and paused, which leaves archived projects out).
	Statuses []string
	// Sort is a ProjectSort value; empty means the API default.
	Sort string
	// Limit is the page size (1 to MaxProjectListLimit); zero means the API
	// default (50).
	Limit int
	// Cursor is the opaque next_cursor of the previous page.
	Cursor string
}

// ListProjects fetches one page of the tenant's projects.
func (c *Client) ListProjects(ctx context.Context, tenantID string, opts ProjectListOptions) (*model.ProjectListResponse, error) {
	if opts.Limit < 0 || opts.Limit > MaxProjectListLimit {
		return nil, fmt.Errorf("project page size %d is out of range: must be 1 to %d (or 0 for the default)",
			opts.Limit, MaxProjectListLimit)
	}

	params := url.Values{}
	params.Set("tenant_id", tenantID)
	if opts.Query != "" {
		params.Set("q", opts.Query)
	}
	for _, s := range opts.Statuses {
		params.Add("status", s)
	}
	if opts.Sort != "" {
		params.Set("sort", opts.Sort)
	}
	if opts.Limit > 0 {
		params.Set("limit", strconv.Itoa(opts.Limit))
	}
	if opts.Cursor != "" {
		params.Set("cursor", opts.Cursor)
	}

	var resp model.ProjectListResponse
	if err := c.doAppSec(ctx, http.MethodGet, projectsPath, params, nil, http.StatusOK, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// CreateProject creates a project in the tenant. A name already in use (by a
// project in any status) fails with an *AppSecError whose Code is
// AppSecCodeProjectNameConflict.
func (c *Client) CreateProject(ctx context.Context, tenantID string, req model.ProjectCreateRequest) (*model.Project, error) {
	params := url.Values{}
	params.Set("tenant_id", tenantID)

	var project model.Project
	if err := c.doAppSec(ctx, http.MethodPost, projectsPath, params, req, http.StatusCreated, &project); err != nil {
		return nil, err
	}
	return &project, nil
}

// GetProject fetches one project by id.
func (c *Client) GetProject(ctx context.Context, tenantID, projectID string) (*model.Project, error) {
	if !IsValidProjectID(projectID) {
		return nil, fmt.Errorf("invalid project id %q", projectID)
	}
	params := url.Values{}
	params.Set("tenant_id", tenantID)
	// recent_scans=0: the CLI needs the project's identity and status, not
	// its run history.
	params.Set("recent_scans", "0")

	var project model.Project
	if err := c.doAppSec(ctx, http.MethodGet, projectsPath+"/"+projectID, params, nil, http.StatusOK, &project); err != nil {
		return nil, err
	}
	return &project, nil
}

// doAppSec sends one AppSec API request and decodes a wantStatus response into
// out. Any other status is returned as an *AppSecError.
func (c *Client) doAppSec(ctx context.Context, method, path string, params url.Values, body any, wantStatus int, out any) error {
	endpoint, err := c.appSecURL(path, params)
	if err != nil {
		return err
	}

	var reqBody io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %w", err)
		}
		// bytes.Reader lets the retrying client replay the body.
		reqBody = bytes.NewReader(bodyBytes)
	}

	// armis:ignore cwe:918 reason:baseURL validated in NewClient (HTTPS enforced); path is a constant plus a PathEscaped id
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reqBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if err := c.setAuthHeader(ctx, req); err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s failed: %w", method, path, err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body read-only

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, MaxAPIResponseSize))
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if c.debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] AppSec %s %s?%s -> %d\n", method, path, params.Encode(), resp.StatusCode)
	}

	if resp.StatusCode != wantStatus {
		return parseAppSecError(resp.StatusCode, respBytes)
	}
	if err := json.Unmarshal(respBytes, out); err != nil {
		return fmt.Errorf("failed to decode %s %s response: %w", method, path, err)
	}
	return nil
}

// projectIDPattern matches an AppSec project id. Ids are opaque ("p_507f..."),
// so this allows any id the API mints while keeping path syntax ('/', '.',
// '?', '%', '#') out of the URL.
var projectIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// appSecPathPattern is the allowlist of AppSec routes the CLI calls: the
// projects collection, or one project by id.
var appSecPathPattern = regexp.MustCompile(`^` + regexp.QuoteMeta(projectsPath) + `(/[A-Za-z0-9_-]{1,128})?$`)

// IsValidProjectID reports whether id has the shape of an AppSec project id.
func IsValidProjectID(id string) bool {
	return projectIDPattern.MatchString(id)
}

// appSecURL builds the URL of an AppSec API call on the configured base URL.
// The path must be one of the allowlisted routes, and the result is checked to
// stay on the base URL's scheme and host, so no path can send the request (or
// its credentials) anywhere else: a path starting "@evil.example", say, would
// otherwise turn the base host into userinfo.
func (c *Client) appSecURL(path string, params url.Values) (string, error) {
	if !appSecPathPattern.MatchString(path) {
		return "", fmt.Errorf("invalid AppSec API path %q", path)
	}
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base URL: %w", err)
	}
	u, err := url.Parse(strings.TrimSuffix(c.baseURL, "/") + path)
	if err != nil {
		return "", fmt.Errorf("invalid AppSec API URL: %w", err)
	}
	if u.Scheme != base.Scheme || u.Host != base.Host || u.User != nil {
		return "", fmt.Errorf("AppSec API URL %q does not stay on the API host %q", u.Redacted(), base.Host)
	}
	u.RawQuery = params.Encode()
	return u.String(), nil
}

// parseAppSecError builds an *AppSecError from an error body. The API answers
// in one of three shapes:
//
//   - the AppSec envelope {"detail": "...", "error": "code", "context": {...}};
//   - FastAPI's validation body {"detail": [{"loc": [...], "msg": "..."}]};
//   - a bare {"detail": "..."} (or, from a proxy, anything else).
func parseAppSecError(status int, body []byte) *AppSecError {
	apiErr := &AppSecError{StatusCode: status}

	var envelope struct {
		Detail  json.RawMessage `json:"detail"`
		Error   *string         `json:"error"`
		Context map[string]any  `json:"context"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		apiErr.Detail = truncateDetail(strings.TrimSpace(string(body)))
		return apiErr
	}
	if envelope.Error != nil {
		apiErr.Code = *envelope.Error
	}
	apiErr.Context = envelope.Context

	var detail string
	if err := json.Unmarshal(envelope.Detail, &detail); err == nil {
		apiErr.Detail = detail
		return apiErr
	}
	var items []struct {
		Loc []any  `json:"loc"`
		Msg string `json:"msg"`
	}
	if err := json.Unmarshal(envelope.Detail, &items); err == nil && len(items) > 0 {
		msgs := make([]string, 0, len(items))
		for _, it := range items {
			if field := validationField(it.Loc); field != "" {
				msgs = append(msgs, field+": "+it.Msg)
			} else {
				msgs = append(msgs, it.Msg)
			}
		}
		apiErr.Detail = strings.Join(msgs, "; ")
		return apiErr
	}
	apiErr.Detail = truncateDetail(strings.TrimSpace(string(body)))
	return apiErr
}

// validationField names the field of a FastAPI validation error location such
// as ["body", "name"], dropping the leading "body"/"query" segment.
func validationField(loc []any) string {
	parts := make([]string, 0, len(loc))
	for i, p := range loc {
		s := fmt.Sprint(p)
		if i == 0 && (s == "body" || s == "query" || s == "path" || s == "header") {
			continue
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ".")
}

// truncateDetail bounds an unparseable body kept for an error message, without
// splitting a UTF-8 sequence.
func truncateDetail(s string) string {
	if len(s) <= maxErrorDetailLen {
		return s
	}
	return strings.ToValidUTF8(s[:maxErrorDetailLen], "") + "..."
}
