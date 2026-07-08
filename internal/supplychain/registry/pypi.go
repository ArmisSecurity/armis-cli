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

	// pypiSimpleJSONAccept is the PEP 691 content type for the PyPI Simple API
	// JSON representation, which carries PEP 700 per-file "upload-time" fields.
	// Mirrors the constant the wrap proxy requests (supplychain.pypiSimpleJSONAccept).
	pypiSimpleJSONAccept = "application/vnd.pypi.simple.v1+json"
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
	// simpleAPI selects the PEP 691 Simple API ("<baseURL>/<name>/") instead of
	// PyPI's own legacy JSON API ("<baseURL>/pypi/<name>/json"). Set true only
	// for a configured custom upstream (NewPyPIClientWithHTTP with a non-default
	// baseURL): the legacy endpoint is a PyPI-proprietary API that no
	// artifactory (Nexus, JFrog Artifactory) implements — a custom upstream 404s
	// on it — while every PEP 503-compliant mirror serves the Simple API. The
	// default public path keeps using the legacy API, which returns every
	// version's files in one response instead of requiring the version to
	// already be known.
	simpleAPI bool
	// authHeader is an optional pre-built Authorization value ("Basic <b64>")
	// attached to every release-metadata request, so `supply-chain check` can
	// query an auth-gated PyPI index with the developer's index-url credential.
	// Empty on the public path (pypi.org needs no credential).
	authHeader string
	cache      sync.Map // map[string]map[string][]pypiRelease
	cacheLen   atomic.Int64
}

type pypiResponse struct {
	Releases map[string][]pypiRelease `json:"releases"`
}

type pypiRelease struct {
	UploadTime string `json:"upload_time_iso_8601"`
}

// pypiSimpleFile is one entry in a PEP 691 Simple API "files" array. Only the
// fields the age check needs are decoded; hashes/requires-python/etc. are
// dropped, mirroring the wrap proxy's map[string]json.RawMessage approach but
// with a fixed struct since this client never re-serializes the document.
type pypiSimpleFile struct {
	Filename   string `json:"filename"`
	UploadTime string `json:"upload-time"`
}

type pypiSimpleResponse struct {
	Files []pypiSimpleFile `json:"files"`
}

func NewPyPIClient() *PyPIClient {
	return &PyPIClient{
		httpClient: &http.Client{Timeout: 30 * time.Second, Transport: httpclient.ProxyAwareTransport()},
		baseURL:    defaultPyPIURL,
	}
}

// NewPyPIClientWithHTTP builds a PyPIClient with an injected HTTP client and
// base URL. Two callers use it: tests pointing at an httptest server, and the
// CI `check` path pointing at a configured corporate artifactory (PPSC-994). In
// both cases baseURL is a construction-time value the caller controls — for the
// artifactory case it MUST have passed supplychain.ValidateRegistryURL
// (https-only, no userinfo, no loopback/RFC1918/link-local host) at config-load
// before reaching here, which keeps the cwe:918 suppressions in fetchReleases
// sound now that the URL is configurable. Production age checks against public
// PyPI use NewPyPIClient, which hardcodes pypi.org.
//
// A non-default, non-empty baseURL is assumed to be a custom artifactory and
// switches fetchReleases to the PEP 691 Simple API (see simpleAPI) — the
// legacy "/pypi/<name>/json" endpoint this client otherwise uses is a
// PyPI-proprietary API no artifactory implements.
// armis:ignore cwe:918 reason:baseURL is either "" (defaults to the hardcoded pypi.org constant below) or the config-load-validated registries.pypi value (supplychain.ValidateRegistryURL: https-only, no userinfo, rejects loopback/RFC1918/link-local) per the doc comment above; not a per-request attacker-controlled value
func NewPyPIClientWithHTTP(httpClient *http.Client, baseURL string) *PyPIClient {
	if baseURL == "" {
		baseURL = defaultPyPIURL
	}
	// Trim a trailing slash so fetchReleases' URL join never yields a "//" at
	// the boundary — a configured index URL commonly ends in one. Same
	// normalization as the npm client. A configured registries.pypi URL is
	// required (config.go) to already end in "/simple" (PEP 503); unlike the
	// wrap proxy (which forwards the client's own "/simple/<pkg>/" request path
	// onto the upstream and so must avoid re-adding it), fetchReleasesSimple
	// builds "<baseURL>/<name>/" directly with no separate "/simple" segment of
	// its own, so baseURL keeping its "/simple" suffix is exactly the path PEP
	// 503 artifactories expect — nothing to strip here.
	baseURL = strings.TrimRight(baseURL, "/")
	// Compute custom AFTER normalization: "https://pypi.org/" (trailing slash)
	// must be treated as the default public host, not as a custom artifactory —
	// computing this before TrimRight would make an equivalent default URL take
	// the wrong (Simple API) code path purely due to a cosmetic trailing slash.
	custom := baseURL != strings.TrimRight(defaultPyPIURL, "/")
	// Guard the exported constructor against a nil client: callers that pass nil
	// would otherwise hit a nil-pointer panic at c.httpClient.Do(). Default to
	// the same proxy-aware, timeout-configured client NewPyPIClient uses, so this
	// fallback also honors WinINET/PAC on Windows instead of silently dropping
	// proxy support for the injected-client path.
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second, Transport: httpclient.ProxyAwareTransport()}
	}
	return &PyPIClient{
		httpClient: httpClient,
		baseURL:    baseURL,
		simpleAPI:  custom,
	}
}

// WithAuthHeader sets the Authorization header value ("Basic <b64>") sent on
// every release-metadata request and returns the client for chaining. Mirrors
// the npm client's setter; an empty value is a no-op (public path). Set before
// any concurrent GetPublishDates call.
func (c *PyPIClient) WithAuthHeader(authHeader string) *PyPIClient {
	c.authHeader = authHeader
	return c
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

// fetchReleases resolves a package's per-version release files. It dispatches
// to the legacy PyPI JSON API (public pypi.org) or the PEP 691 Simple API (any
// configured custom artifactory) based on c.simpleAPI — see NewPyPIClientWithHTTP.
func (c *PyPIClient) fetchReleases(ctx context.Context, name string) (map[string][]pypiRelease, error) {
	if cached, ok := c.cache.Load(name); ok {
		return cached.(map[string][]pypiRelease), nil
	}

	var releases map[string][]pypiRelease
	var err error
	if c.simpleAPI {
		releases, err = c.fetchReleasesSimple(ctx, name)
	} else {
		releases, err = c.fetchReleasesLegacy(ctx, name)
	}
	if err != nil {
		return nil, err
	}

	// Memoize, but stop inserting once the cache reaches maxCacheEntries so it
	// cannot grow without bound (CWE-770). LoadOrStore keeps the length count
	// race-free under the concurrent GetPublishDates fan-out.
	if c.cacheLen.Load() < maxCacheEntries {
		if _, loaded := c.cache.LoadOrStore(name, releases); !loaded {
			c.cacheLen.Add(1)
		}
	}
	return releases, nil
}

// fetchReleasesLegacy queries PyPI's own "/pypi/<name>/json" API. This is a
// PyPI-proprietary endpoint no third-party artifactory implements, so it is
// used only for the default public pypi.org path (c.simpleAPI is false).
func (c *PyPIClient) fetchReleasesLegacy(ctx context.Context, name string) (map[string][]pypiRelease, error) {
	encodedName := url.PathEscape(name)
	// armis:ignore cwe:918 reason:baseURL is either the hardcoded pypi.org HTTPS constant (NewPyPIClient) or a custom upstream validated at config-load by supplychain.ValidateRegistryURL (https-only, no userinfo, rejects loopback/RFC1918/link-local) before NewPyPIClientWithHTTP is called; name is regex-validated above and PathEscaped, so neither can alter the host
	reqURL := fmt.Sprintf("%s/pypi/%s/json", c.baseURL, encodedName)
	// armis:ignore cwe:918 reason:reqURL is built from baseURL (pypi.org constant or a config-load-validated custom upstream) + a PathEscaped, regex-validated package name, so the host is not attacker-controlled
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request for %s: %w", name, err)
	}
	req.Header.Set("Accept", "application/json")
	// Forward the developer's index credential when configured so an auth-gated
	// PyPI index answers 200 instead of 401 (the `check` path).
	if c.authHeader != "" {
		req.Header.Set("Authorization", c.authHeader)
	}

	// armis:ignore cwe:918 reason:c.baseURL is either the hardcoded pypi.org HTTPS constant (NewPyPIClient) or a custom upstream validated at config-load by supplychain.ValidateRegistryURL (https-only, no userinfo, rejects loopback/RFC1918/link-local), so the request host is not attacker-controlled; the package name is regex-validated and PathEscaped
	resp, err := c.httpClient.Do(req) //nolint:gosec // G704: reqURL is a constant/config-load-validated registry host + regex-validated, PathEscaped package name
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
	return result.Releases, nil
}

// fetchReleasesSimple queries the PEP 691 Simple API ("<baseURL>/<name>/") and
// regroups its flat per-file list by version (parsed from each filename) so
// the result matches fetchReleasesLegacy's shape and GetPublishDate's existing
// version-lookup logic needs no changes. Used for any configured custom
// upstream (c.simpleAPI is true) — every PEP 503-compliant artifactory
// (Nexus, JFrog Artifactory) serves this API, unlike PyPI's proprietary legacy
// JSON endpoint.
func (c *PyPIClient) fetchReleasesSimple(ctx context.Context, name string) (map[string][]pypiRelease, error) {
	encodedName := url.PathEscape(name)
	// armis:ignore cwe:918 reason:baseURL is a custom upstream validated at config-load by supplychain.ValidateRegistryURL (https-only, no userinfo, rejects loopback/RFC1918/link-local) before NewPyPIClientWithHTTP is called; name is regex-validated above and PathEscaped, so neither can alter the host
	reqURL := fmt.Sprintf("%s/%s/", c.baseURL, encodedName)
	// armis:ignore cwe:918 reason:reqURL is built from baseURL (a config-load-validated custom upstream) + a PathEscaped, regex-validated package name, so the host is not attacker-controlled
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request for %s: %w", name, err)
	}
	// Request the PEP 691 JSON form so the response carries PEP 700 per-file
	// upload-time fields; the default Simple API HTML has no timestamps. Mirrors
	// the wrap proxy's handleMetadataFiltering.
	req.Header.Set("Accept", pypiSimpleJSONAccept)
	if c.authHeader != "" {
		req.Header.Set("Authorization", c.authHeader)
	}

	// armis:ignore cwe:918 reason:c.baseURL is a custom upstream validated at config-load by supplychain.ValidateRegistryURL (https-only, no userinfo, rejects loopback/RFC1918/link-local), so the request host is not attacker-controlled; the package name is regex-validated and PathEscaped
	resp, err := c.httpClient.Do(req) //nolint:gosec // G704: reqURL is a config-load-validated registry host + regex-validated, PathEscaped package name
	if err != nil {
		return nil, fmt.Errorf("fetching PyPI Simple API metadata for %s: %w", name, err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close on read path

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("package %q not found on configured registry", name)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("configured registry returned %d for %s", resp.StatusCode, name)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading registry response for %s: %w", name, err)
	}
	if int64(len(body)) > maxResponseSize {
		return nil, fmt.Errorf("registry response for %s too large (max %d bytes)", name, maxResponseSize)
	}

	var simple pypiSimpleResponse
	if err := json.Unmarshal(body, &simple); err != nil {
		return nil, fmt.Errorf("parsing registry Simple API response for %s: %w", name, err)
	}

	releases := make(map[string][]pypiRelease, len(simple.Files))
	for _, f := range simple.Files {
		ver := pypiVersionFromFilename(f.Filename)
		if ver == "" {
			continue
		}
		releases[ver] = append(releases[ver], pypiRelease{UploadTime: f.UploadTime})
	}
	return releases, nil
}

// pypiVersionFromFilename extracts the version component from a wheel or sdist
// filename. Wheels and sdists use different grammars, so they are parsed
// separately. Returns "" if the pattern does not match. Duplicated from the
// wrap proxy's identical helper (supplychain.pypiVersionFromFilename, package-
// private there) rather than exported across the package boundary for one
// small pure function.
func pypiVersionFromFilename(filename string) string {
	// Wheels (and the legacy egg format) carry trailing build/interpreter/
	// platform tags after the version, e.g.
	// "{name}-{version}-{python}-{abi}-{platform}.whl". PEP 427 normalizes the
	// distribution so it never contains '-' (runs of [-_.] collapse to '_'), so
	// the version is reliably the second '-'-delimited field.
	if strings.HasSuffix(filename, ".whl") || strings.HasSuffix(filename, ".egg") {
		base := filename[:strings.LastIndex(filename, ".")]
		parts := strings.SplitN(base, "-", 3)
		if len(parts) < 2 {
			return ""
		}
		return parts[1]
	}

	// sdists are "{name}-{version}{ext}" with no trailing tags. Unlike wheels the
	// project name is NOT normalized, so it may legitimately contain '-' (e.g.
	// "zope-interface-6.0.tar.gz"). PEP 440 versions never contain '-', so the
	// version is everything after the FINAL '-'. Splitting on the first '-' (as a
	// single shared parser would) misreads such names — yielding "interface".
	name := filename
	for _, ext := range []string{".tar.gz", ".tar.bz2", ".zip"} {
		if strings.HasSuffix(name, ext) {
			name = name[:len(name)-len(ext)]
			break
		}
	}
	idx := strings.LastIndex(name, "-")
	if idx <= 0 || idx == len(name)-1 {
		return ""
	}
	return name[idx+1:]
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
