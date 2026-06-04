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

	"github.com/cenkalti/backoff/v4"
)

const (
	defaultMavenURL = "https://search.maven.org"
	// mavenMaxElapsed bounds the total time spent retrying a single coordinate
	// against Maven Central's rate limiter before giving up.
	mavenMaxElapsed     = 30 * time.Second
	mavenInitialBackoff = 500 * time.Millisecond
)

var validMavenCoordinate = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// MavenClient queries Maven Central for artifact publication dates. Unlike the
// npm and PyPI clients, Maven Central rate-limits aggressively (HTTP 429), so
// each lookup is wrapped in an exponential backoff.
type MavenClient struct {
	httpClient *http.Client
	baseURL    string
	cache      sync.Map // map[string]time.Time, keyed by "group:artifact@version"
	cacheLen   atomic.Int64
}

type mavenSearchResponse struct {
	Response struct {
		Docs []struct {
			Timestamp int64 `json:"timestamp"`
		} `json:"docs"`
	} `json:"response"`
}

func NewMavenClient() *MavenClient {
	return &MavenClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    defaultMavenURL,
	}
}

// NewMavenClientWithHTTP builds a MavenClient with an injected HTTP client and
// base URL. It exists for tests that point the client at an httptest server; the
// baseURL is therefore a trusted construction-time value, not request- or
// network-derived input. Production code uses NewMavenClient, which hardcodes
// the search.maven.org HTTPS endpoint.
func NewMavenClientWithHTTP(client *http.Client, baseURL string) *MavenClient {
	if baseURL == "" {
		baseURL = defaultMavenURL
	}
	return &MavenClient{
		httpClient: client,
		baseURL:    baseURL,
	}
}

func (c *MavenClient) GetPublishDate(ctx context.Context, name, version string) (time.Time, error) {
	parts := strings.SplitN(name, ":", 2)
	if len(parts) != 2 {
		return time.Time{}, fmt.Errorf("invalid maven coordinate: %s (expected group:artifact)", name)
	}
	groupID, artifactID := parts[0], parts[1]

	if !validMavenCoordinate.MatchString(groupID) {
		return time.Time{}, fmt.Errorf("invalid maven groupId: %s", groupID)
	}
	if !validMavenCoordinate.MatchString(artifactID) {
		return time.Time{}, fmt.Errorf("invalid maven artifactId: %s", artifactID)
	}

	cacheKey := name + "@" + version
	if cached, ok := c.cache.Load(cacheKey); ok {
		return cached.(time.Time), nil
	}

	var publishTime time.Time
	operation := func() error {
		t, err := c.fetchPublishDate(ctx, groupID, artifactID, version)
		if err != nil {
			return err
		}
		publishTime = t
		return nil
	}

	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = mavenMaxElapsed
	bo.InitialInterval = mavenInitialBackoff

	if err := backoff.Retry(operation, backoff.WithContext(bo, ctx)); err != nil {
		return time.Time{}, err
	}

	// Memoize, but stop inserting once the cache reaches maxCacheEntries so it
	// cannot grow without bound (CWE-770).
	if c.cacheLen.Load() < maxCacheEntries {
		if _, loaded := c.cache.LoadOrStore(cacheKey, publishTime); !loaded {
			c.cacheLen.Add(1)
		}
	}
	return publishTime, nil
}

func (c *MavenClient) fetchPublishDate(ctx context.Context, groupID, artifactID, version string) (time.Time, error) {
	q := fmt.Sprintf(`g:"%s" AND a:"%s" AND v:"%s"`, groupID, artifactID, version)
	// armis:ignore cwe:918 reason:baseURL is a trusted construction-time config value (production NewMavenClient hardcodes the search.maven.org HTTPS constant; the URL-accepting NewMavenClientWithHTTP is test-only); groupID/artifactID/version are regex-validated and the query is QueryEscaped, so the host is not attacker-controlled
	reqURL := fmt.Sprintf("%s/solrsearch/select?q=%s&rows=1&wt=json", c.baseURL, url.QueryEscape(q))

	// armis:ignore cwe:918 reason:reqURL is built from the trusted baseURL constant + a QueryEscaped query of regex-validated coordinates, so the host is not attacker-controlled
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return time.Time{}, backoff.Permanent(fmt.Errorf("creating request: %w", err))
	}
	req.Header.Set("Accept", "application/json")

	// armis:ignore cwe:918 reason:c.baseURL is a trusted construction-time config value (production NewMavenClient hardcodes the search.maven.org HTTPS constant; the URL-accepting NewMavenClientWithHTTP is test-only), so the request host is not attacker-controlled; coordinates are regex-validated and QueryEscaped
	resp, err := c.httpClient.Do(req) //nolint:gosec // G704: reqURL is a constant/configured registry host + regex-validated, QueryEscaped coordinates
	if err != nil {
		return time.Time{}, fmt.Errorf("fetching maven metadata: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close on read path

	// A 429 is transient: return a plain (retryable) error so backoff retries it.
	if resp.StatusCode == http.StatusTooManyRequests {
		return time.Time{}, fmt.Errorf("maven central rate limited (429)")
	}
	// Any other non-200 is permanent: wrap so backoff stops immediately.
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, backoff.Permanent(fmt.Errorf("maven central returned %d for %s:%s", resp.StatusCode, groupID, artifactID))
	}

	// Read one byte past the cap so an oversize response is detectable instead of
	// being silently truncated and failing as a confusing JSON parse error.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return time.Time{}, backoff.Permanent(fmt.Errorf("reading response: %w", err))
	}
	if int64(len(body)) > maxResponseSize {
		return time.Time{}, backoff.Permanent(fmt.Errorf("maven central response for %s:%s too large (max %d bytes)", groupID, artifactID, maxResponseSize))
	}

	var searchResp mavenSearchResponse
	if err := json.Unmarshal(body, &searchResp); err != nil {
		return time.Time{}, backoff.Permanent(fmt.Errorf("parsing maven response: %w", err))
	}

	if len(searchResp.Response.Docs) == 0 {
		return time.Time{}, backoff.Permanent(fmt.Errorf("artifact not found on maven central: %s:%s:%s", groupID, artifactID, version))
	}

	timestamp := searchResp.Response.Docs[0].Timestamp
	return time.UnixMilli(timestamp), nil
}

func (c *MavenClient) GetPublishDates(ctx context.Context, packages []PackageRequest) []QueryResult {
	results := make([]QueryResult, len(packages))
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup

	for i, pkg := range packages {
		// Acquire the semaphore before spawning so that goroutine creation itself
		// is bounded by maxConcurrent rather than launching one stack per package.
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
