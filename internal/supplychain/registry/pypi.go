package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/httpclient"
)

const (
	defaultPyPIURL = "https://pypi.org"
)

var validPyPIPackageName = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$`)

// pypiSeparatorRun matches any run of the PEP 503 separator characters (-, _, .).
// PyPI canonicalizes a name by lowercasing and collapsing each such run to a
// single hyphen, so "My__Package" and "my.package" both normalize to
// "my-package". Collapsing runs (rather than replacing each separator
// one-for-one) is what keeps the queried name aligned with the key PyPI files
// the metadata under — a one-for-one replace would turn "my__pkg" into
// "my--pkg" and 404.
var pypiSeparatorRun = regexp.MustCompile(`[-_.]+`)

type PyPIClient struct {
	httpClient *http.Client
	baseURL    string
	cache      sync.Map // map[string]map[string][]pypiRelease
	cacheLen   atomic.Int64
}

type pypiResponse struct {
	Releases map[string][]pypiRelease `json:"releases"`
}

type pypiRelease struct {
	UploadTime string `json:"upload_time_iso_8601"`
}

func NewPyPIClient() *PyPIClient {
	return &PyPIClient{
		httpClient: &http.Client{Timeout: 30 * time.Second, Transport: httpclient.ProxyAwareTransport()},
		baseURL:    defaultPyPIURL,
	}
}

// NewPyPIClientWithHTTP builds a PyPIClient with an injected HTTP client and
// base URL. It exists for tests that point the client at an httptest server;
// the baseURL is therefore a trusted construction-time value, not request- or
// network-derived input. Production code uses NewPyPIClient, which hardcodes
// the pypi.org HTTPS endpoint.
func NewPyPIClientWithHTTP(httpClient *http.Client, baseURL string) *PyPIClient {
	if baseURL == "" {
		baseURL = defaultPyPIURL
	}
	// Guard the exported constructor against a nil client: callers that pass nil
	// would otherwise hit a nil-pointer panic at c.httpClient.Do(). Default to
	// the same timeout-configured client NewPyPIClient uses.
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &PyPIClient{
		httpClient: httpClient,
		baseURL:    baseURL,
	}
}

func (c *PyPIClient) GetPublishDate(ctx context.Context, name, version string) (time.Time, error) {
	normalized := normalizePyPIName(name)
	if !validPyPIPackageName.MatchString(normalized) {
		return time.Time{}, fmt.Errorf("invalid PyPI package name: %q", name)
	}

	releases, err := c.fetchReleases(ctx, normalized)
	if err != nil {
		return time.Time{}, err
	}

	files, ok := releases[version]
	if !ok || len(files) == 0 {
		// PyPI keys releases by the version string as uploaded, but PEP 440
		// treats e.g. "2.0" and "2.0.0" (and "1.0.0a1" / "1.0.0.alpha1") as the
		// same version. A lockfile may pin a spelling that differs from PyPI's
		// key, so fall back to a normalized comparison before giving up —
		// otherwise the package is silently skipped with a warning instead of
		// being age-checked, a gap in a control whose whole job is to block.
		if files, ok = lookupReleaseNormalized(releases, version); !ok || len(files) == 0 {
			return time.Time{}, fmt.Errorf("version %q not found for %s", version, name)
		}
	}

	// Use the earliest upload time for the version
	var earliest time.Time
	for _, f := range files {
		if f.UploadTime == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, f.UploadTime)
		if err != nil {
			t, err = time.Parse("2006-01-02T15:04:05", f.UploadTime)
			if err != nil {
				continue
			}
		}
		if earliest.IsZero() || t.Before(earliest) {
			earliest = t
		}
	}

	if earliest.IsZero() {
		return time.Time{}, fmt.Errorf("no upload time found for %s@%s", name, version)
	}

	return earliest, nil
}

func (c *PyPIClient) GetPublishDates(ctx context.Context, packages []PackageRequest) []QueryResult {
	results := make([]QueryResult, len(packages))
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup

	for i, pkg := range packages {
		// Acquire the semaphore before spawning so that goroutine creation
		// itself is bounded by maxConcurrent. Acquiring it inside the goroutine
		// would launch one stack per package up front (thousands for a large
		// lockfile) just to park them all on the channel.
		sem <- struct{}{}
		wg.Add(1)
		go func(idx int, name, version string) {
			defer wg.Done()
			defer func() { <-sem }()

			publishTime, err := c.GetPublishDate(ctx, name, version)
			results[idx] = QueryResult{
				Name:        name,
				Version:     version,
				PublishTime: publishTime,
				Err:         err,
			}
		}(i, pkg.Name, pkg.Version)
	}

	wg.Wait()
	return results
}

func (c *PyPIClient) fetchReleases(ctx context.Context, name string) (map[string][]pypiRelease, error) {
	if cached, ok := c.cache.Load(name); ok {
		return cached.(map[string][]pypiRelease), nil
	}

	encodedName := url.PathEscape(name)
	// armis:ignore cwe:918 reason:baseURL is a trusted construction-time config value (production NewPyPIClient hardcodes the pypi.org HTTPS constant; the URL-accepting NewPyPIClientWithHTTP is test-only); name is regex-validated above and PathEscaped, so it cannot alter the host
	reqURL := fmt.Sprintf("%s/pypi/%s/json", c.baseURL, encodedName)
	// armis:ignore cwe:918 reason:reqURL is built from the trusted baseURL constant + a PathEscaped, regex-validated package name, so the host is not attacker-controlled
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request for %s: %w", name, err)
	}
	req.Header.Set("Accept", "application/json")

	// armis:ignore cwe:918 reason:c.baseURL is a trusted construction-time config value (production NewPyPIClient hardcodes the pypi.org HTTPS constant; the URL-accepting NewPyPIClientWithHTTP is test-only), so the request host is not attacker-controlled; the package name is regex-validated and PathEscaped
	resp, err := c.httpClient.Do(req) //nolint:gosec // G704: reqURL is a constant/configured registry host + regex-validated, PathEscaped package name
	if err != nil {
		return nil, fmt.Errorf("fetching PyPI metadata for %s: %w", name, err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close on read path

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("package %q not found on PyPI", name)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("PyPI returned %d for %s", resp.StatusCode, name)
	}

	// Read one byte past the cap so an oversize response is detectable: a body
	// at exactly maxResponseSize reads to maxResponseSize, while anything larger
	// yields maxResponseSize+1 bytes. Without this, LimitReader would silently
	// truncate and the failure would surface as a confusing JSON parse error.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading PyPI response for %s: %w", name, err)
	}
	if int64(len(body)) > maxResponseSize {
		return nil, fmt.Errorf("PyPI response for %s too large (max %d bytes)", name, maxResponseSize)
	}

	var result pypiResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing PyPI response for %s: %w", name, err)
	}

	// Memoize, but stop inserting once the cache reaches maxCacheEntries so it
	// cannot grow without bound (CWE-770). LoadOrStore keeps the length count
	// race-free under the concurrent GetPublishDates fan-out.
	if c.cacheLen.Load() < maxCacheEntries {
		if _, loaded := c.cache.LoadOrStore(name, result.Releases); !loaded {
			c.cacheLen.Add(1)
		}
	}
	return result.Releases, nil
}

// NormalizePyPIName applies PEP 503 name normalization: lowercase the name and
// collapse every run of -, _, or . to a single hyphen. It is the single source
// of truth for PyPI name canonicalization — the check package's lockfile parsers
// delegate to it so the name written into a registry query always matches the
// name PyPI files its metadata under.
func NormalizePyPIName(name string) string {
	return pypiSeparatorRun.ReplaceAllString(strings.ToLower(name), "-")
}

func normalizePyPIName(name string) string {
	return NormalizePyPIName(name)
}

// lookupReleaseNormalized finds a release whose key matches version under PEP
// 440 normalization, for when the lockfile and PyPI spell the same version
// differently (e.g. "2.0" vs "2.0.0"). It scans the releases map, so it is the
// O(n) fallback used only after the direct O(1) lookup misses.
func lookupReleaseNormalized(releases map[string][]pypiRelease, version string) ([]pypiRelease, bool) {
	target := normalizeVersion(version)
	for key, files := range releases {
		if normalizeVersion(key) == target {
			return files, true
		}
	}
	return nil, false
}

// normalizeVersion produces a comparison key for a PEP 440 version string that
// is tolerant of the spellings that differ only cosmetically: it lowercases,
// drops a leading "v", unifies pre/post/dev separators, and trims trailing
// ".0" release segments so "2.0", "2.0.0", and "2.0.0.0" compare equal. It is a
// pragmatic subset of full PEP 440 normalization — enough to align a lockfile
// pin with PyPI's release key without pulling in a version-parsing dependency.
func normalizeVersion(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimPrefix(v, "v")
	// Collapse the separators PEP 440 treats as equivalent around pre/post/dev
	// segments (e.g. "1.0.0.alpha.1" / "1.0.0-alpha1" → "1.0.0alpha1") so only
	// the release-number trimming below distinguishes versions.
	v = strings.NewReplacer("-", "", "_", "", ".alpha", "alpha", ".beta", "beta",
		".rc", "rc", ".dev", "dev", ".post", "post").Replace(v)

	// Trim trailing ".0" segments from the leading numeric release portion so
	// "2.0" and "2.0.0" share a key. Only the dotted numeric prefix is trimmed;
	// any pre/post/dev suffix is left intact.
	prefixEnd := len(v)
	for i, r := range v {
		if (r < '0' || r > '9') && r != '.' {
			prefixEnd = i
			break
		}
	}
	release, suffix := v[:prefixEnd], v[prefixEnd:]
	segments := strings.Split(release, ".")
	for len(segments) > 1 && segments[len(segments)-1] == "0" {
		segments = segments[:len(segments)-1]
	}
	return strings.Join(segments, ".") + suffix
}
