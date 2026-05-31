package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	defaultPyPIURL = "https://pypi.org"
)

var validPyPIPackageName = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$`)

type PyPIClient struct {
	httpClient *http.Client
	baseURL    string
	cache      sync.Map
}

type pypiResponse struct {
	Releases map[string][]pypiRelease `json:"releases"`
}

type pypiRelease struct {
	UploadTime string `json:"upload_time_iso_8601"`
}

func NewPyPIClient() *PyPIClient {
	return &PyPIClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    defaultPyPIURL,
	}
}

func NewPyPIClientWithHTTP(httpClient *http.Client, baseURL string) *PyPIClient {
	if baseURL == "" {
		baseURL = defaultPyPIURL
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
		return time.Time{}, fmt.Errorf("version %q not found for %s", version, name)
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

func (c *PyPIClient) GetPublishDates(ctx context.Context, packages []struct{ Name, Version string }) []QueryResult {
	results := make([]QueryResult, len(packages))
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup

	for i, pkg := range packages {
		wg.Add(1)
		go func(idx int, name, version string) {
			defer wg.Done()
			sem <- struct{}{}
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

	reqURL := fmt.Sprintf("%s/pypi/%s/json", c.baseURL, name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil) //nolint:gosec // name is validated
	if err != nil {
		return nil, fmt.Errorf("creating request for %s: %w", name, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching PyPI metadata for %s: %w", name, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("package %q not found on PyPI", name)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("PyPI returned %d for %s", resp.StatusCode, name)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("reading PyPI response for %s: %w", name, err)
	}

	var result pypiResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing PyPI response for %s: %w", name, err)
	}

	c.cache.Store(name, result.Releases)
	return result.Releases, nil
}

func normalizePyPIName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.ReplaceAll(name, ".", "-")
	return name
}
