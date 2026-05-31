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
	"time"

	"github.com/cenkalti/backoff/v4"
)

const (
	defaultMavenURL   = "https://search.maven.org"
	mavenMaxConcurrent = 5
)

var validMavenCoordinate = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// MavenClient queries Maven Central for artifact publication dates.
type MavenClient struct {
	httpClient  *http.Client
	baseURL     string
	cache       sync.Map
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

func NewMavenClientWithHTTP(client *http.Client, baseURL string) *MavenClient {
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
	bo.MaxElapsedTime = 30 * time.Second
	bo.InitialInterval = 500 * time.Millisecond

	if err := backoff.Retry(operation, backoff.WithContext(bo, ctx)); err != nil {
		return time.Time{}, err
	}

	c.cache.Store(cacheKey, publishTime)
	return publishTime, nil
}

func (c *MavenClient) fetchPublishDate(ctx context.Context, groupID, artifactID, version string) (time.Time, error) {
	q := fmt.Sprintf(`g:"%s" AND a:"%s" AND v:"%s"`, groupID, artifactID, version)
	reqURL := fmt.Sprintf("%s/solrsearch/select?q=%s&rows=1&wt=json", c.baseURL, url.QueryEscape(q))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return time.Time{}, backoff.Permanent(fmt.Errorf("creating request: %w", err))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return time.Time{}, fmt.Errorf("fetching maven metadata: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode == http.StatusTooManyRequests {
		return time.Time{}, fmt.Errorf("maven central rate limited (429)")
	}
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, backoff.Permanent(fmt.Errorf("maven central returned %d for %s:%s", resp.StatusCode, groupID, artifactID))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return time.Time{}, backoff.Permanent(fmt.Errorf("reading response: %w", err))
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

// RateLimitError indicates the registry rate-limited the request.
type RateLimitError struct {
	StatusCode int
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("rate limited (HTTP %d)", e.StatusCode)
}

func (c *MavenClient) GetPublishDates(ctx context.Context, packages []struct{ Name, Version string }) []QueryResult {
	results := make([]QueryResult, len(packages))
	sem := make(chan struct{}, mavenMaxConcurrent)
	var wg sync.WaitGroup

	for i, pkg := range packages {
		wg.Add(1)
		go func(idx int, p struct{ Name, Version string }) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			publishTime, err := c.GetPublishDate(ctx, p.Name, p.Version)
			results[idx] = QueryResult{
				Name:        p.Name,
				Version:     p.Version,
				PublishTime: publishTime,
				Err:         err,
			}
		}(i, pkg)
	}

	wg.Wait()
	return results
}
