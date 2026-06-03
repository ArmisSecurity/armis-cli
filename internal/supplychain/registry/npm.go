// Package registry provides clients for querying package registry APIs.
package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultRegistryURL = "https://registry.npmjs.org"
	maxResponseSize    = 20 * 1024 * 1024 // 20MB
	maxConcurrent      = 10
	// maxCacheEntries bounds the metadata memo so the map cannot grow without
	// limit (CWE-770) if a client is reused across many lookups — e.g. a future
	// long-lived consumer or a pathologically large lockfile. The cap is far
	// above any realistic single-project package count; once reached the client
	// simply stops memoizing and re-fetches on miss rather than evicting.
	maxCacheEntries = 10000
)

var validPackageName = regexp.MustCompile(`^(@[a-z0-9\-~][a-z0-9\-._~]*/)?[a-z0-9\-~][a-z0-9\-._~]*$`)

type Client struct {
	httpClient  *http.Client
	registryURL string
	cache       sync.Map // map[string]*registryResponse
	cacheLen    atomic.Int64
}

type registryResponse struct {
	Time map[string]string `json:"time"`
}

// PackageRequest identifies a single package version to look up. It is shared
// by GetPublishDates and its callers so the API does not rely on an anonymous
// struct type that every call site would otherwise have to redeclare verbatim
// (and that any future field addition would break across all of them).
type PackageRequest struct {
	Name    string
	Version string
}

type QueryResult struct {
	Name        string
	Version     string
	PublishTime time.Time
	Err         error
}

func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		registryURL: defaultRegistryURL,
	}
}

// NewClientWithHTTP builds a Client with an injected HTTP client and registry
// URL. It exists for tests that point the client at an httptest server; the
// registryURL is therefore a trusted construction-time value, not request- or
// network-derived input. Production code uses NewClient, which hardcodes the
// npmjs.org HTTPS endpoint.
func NewClientWithHTTP(httpClient *http.Client, registryURL string) *Client {
	if registryURL == "" {
		registryURL = defaultRegistryURL
	}
	return &Client{
		httpClient:  httpClient,
		registryURL: registryURL,
	}
}

func (c *Client) GetPublishDate(ctx context.Context, name, version string) (time.Time, error) {
	if !validPackageName.MatchString(name) {
		return time.Time{}, fmt.Errorf("invalid package name: %q", name)
	}

	resp, err := c.fetchMetadata(ctx, name)
	if err != nil {
		return time.Time{}, err
	}

	timeStr, ok := resp.Time[version]
	if !ok {
		return time.Time{}, fmt.Errorf("version %q not found in registry metadata for %s", version, name)
	}

	t, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing publish time for %s@%s: %w", name, version, err)
	}

	return t, nil
}

func (c *Client) GetPublishDates(ctx context.Context, packages []PackageRequest) []QueryResult {
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

func (c *Client) fetchMetadata(ctx context.Context, name string) (*registryResponse, error) {
	if cached, ok := c.cache.Load(name); ok {
		return cached.(*registryResponse), nil
	}

	encodedName := url.PathEscape(name)
	// armis:ignore cwe:918 reason:registryURL is a trusted construction-time config value (production NewClient hardcodes the npmjs.org HTTPS constant; the URL-accepting NewClientWithHTTP is test-only); name is regex-validated above and PathEscaped, so it cannot alter the host
	// armis:ignore cwe:918 reason:reqURL is built from the trusted registryURL constant (production NewClient hardcodes the npmjs.org HTTPS constant) + a PathEscaped, regex-validated package name, so the host is not attacker-controlled
	reqURL := fmt.Sprintf("%s/%s", c.registryURL, encodedName)
	// armis:ignore cwe:918 reason:reqURL is built from the trusted registryURL constant + a PathEscaped, regex-validated package name, so the host is not attacker-controlled
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request for %s: %w", name, err)
	}
	req.Header.Set("Accept", "application/json")

	// armis:ignore cwe:918 reason:c.registryURL is a trusted construction-time config value (production NewClient hardcodes the npmjs.org HTTPS constant; the URL-accepting NewClientWithHTTP is test-only), so the request host is not attacker-controlled; the package name is regex-validated and PathEscaped
	resp, err := c.httpClient.Do(req) //nolint:gosec // G704: reqURL is a constant/configured registry host + regex-validated, PathEscaped package name
	if err != nil {
		return nil, fmt.Errorf("fetching metadata for %s: %w", name, err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close on read path

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("package %q not found in registry", name)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry returned %d for %s", resp.StatusCode, name)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("reading response for %s: %w", name, err)
	}

	var result registryResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing registry response for %s: %w", name, err)
	}

	// Memoize, but stop inserting once the cache reaches maxCacheEntries so it
	// cannot grow without bound (CWE-770). LoadOrStore keeps the length count
	// race-free under the concurrent GetPublishDates fan-out: only the goroutine
	// that actually inserts a new key bumps cacheLen, and a duplicate concurrent
	// fetch of the same name is counted once.
	if c.cacheLen.Load() < maxCacheEntries {
		if _, loaded := c.cache.LoadOrStore(name, &result); !loaded {
			c.cacheLen.Add(1)
		}
	}
	return &result, nil
}
