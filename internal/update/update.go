// Package update provides version update checking for the CLI.
package update

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/util"
)

const (
	// githubReleasesURL is the GitHub API endpoint for the latest release.
	githubReleasesURL = "https://api.github.com/repos/ArmisSecurity/armis-cli/releases/latest"

	// cacheTTL is how long to cache the version check result.
	cacheTTL = 24 * time.Hour

	// checkTimeout is the maximum time for a version check.
	checkTimeout = 10 * time.Second

	// cacheFileName is the name of the cache file.
	cacheFileName = "update-check.json"

	// cacheDirName is the subdirectory name for cache files.
	cacheDirName = "armis-cli"
)

// CheckResult holds the result of a version check.
type CheckResult struct {
	LatestVersion  string
	CurrentVersion string
}

// cacheFile is the on-disk JSON structure for persisting check results.
type cacheFile struct {
	LatestVersion string    `json:"latest_version"`
	CheckedAt     time.Time `json:"checked_at"`
}

// githubRelease is the minimal structure from the GitHub releases API.
type githubRelease struct {
	TagName string `json:"tag_name"`
}

// Checker performs version update checks.
type Checker struct {
	currentVersion string
	githubAPIURL   string
	cacheTTL       time.Duration
	cacheDir       string // for testing; empty means use os.UserCacheDir()
	httpClient     *http.Client
}

// NewChecker creates a version update checker.
// currentVersion should be the semver version (e.g., "1.0.7").
func NewChecker(currentVersion string) *Checker {
	return &Checker{
		currentVersion: currentVersion,
		githubAPIURL:   githubReleasesURL,
		cacheTTL:       cacheTTL,
		httpClient: &http.Client{
			Timeout: checkTimeout,
		},
	}
}

// CheckInBackground starts a non-blocking version check.
// Returns a channel that will receive at most one *CheckResult.
// The channel is closed when the check completes (or is skipped).
// If the result is nil, no update notification should be shown.
func (c *Checker) CheckInBackground(ctx context.Context) <-chan *CheckResult {
	ch := make(chan *CheckResult, 1)

	// Use a short-lived context so the background check does not hold
	// the process open.
	checkCtx, cancel := context.WithTimeout(ctx, checkTimeout)

	go func() {
		defer cancel()
		defer close(ch)
		result := c.check(checkCtx)
		if result != nil {
			ch <- result
		}
	}()

	return ch
}

// check performs the actual version check (blocking).
func (c *Checker) check(ctx context.Context) *CheckResult {
	// Try reading cache first
	cached := c.readCache()
	if cached != nil && time.Since(cached.CheckedAt) < c.cacheTTL {
		// Cache is fresh -- use cached version
		if IsNewer(c.currentVersion, cached.LatestVersion) {
			return &CheckResult{
				LatestVersion:  cached.LatestVersion,
				CurrentVersion: c.currentVersion,
			}
		}
		return nil // no update needed
	}

	// Fetch from GitHub
	latest, err := c.fetchLatestVersion(ctx)
	if err != nil {
		return nil // silently fail
	}

	// Don't cache empty tags - retry on next check
	if latest == "" {
		return nil
	}

	// Write to cache (best-effort)
	c.writeCache(&cacheFile{
		LatestVersion: latest,
		CheckedAt:     time.Now(),
	})

	// Compare
	if IsNewer(c.currentVersion, latest) {
		return &CheckResult{
			LatestVersion:  latest,
			CurrentVersion: c.currentVersion,
		}
	}

	return nil
}

// fetchLatestVersion queries the GitHub releases API.
func (c *Checker) fetchLatestVersion(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.githubAPIURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "armis-cli-update-check")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	// Limit body size to prevent memory issues
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", err
	}

	var release githubRelease
	if err := json.Unmarshal(body, &release); err != nil {
		return "", err
	}

	return release.TagName, nil
}

// getCacheFilePath returns the path to the cache file.
func (c *Checker) getCacheFilePath() string {
	if c.cacheDir != "" {
		// Validate cacheDir to prevent path traversal (CWE-73)
		sanitized, err := util.SanitizePath(c.cacheDir)
		if err != nil {
			return "" // invalid cacheDir, disable caching
		}
		return filepath.Join(sanitized, cacheFileName)
	}
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return "" // no caching possible
	}
	return filepath.Join(cacheDir, cacheDirName, cacheFileName)
}

// readCache attempts to read a cached check result.
// Returns nil if cache is missing or corrupt.
func (c *Checker) readCache() *cacheFile {
	path := c.getCacheFilePath()
	if path == "" {
		return nil
	}
	// Validate the final path before reading to prevent path traversal (CWE-73)
	sanitizedPath, err := util.SanitizePath(path)
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(sanitizedPath) //nolint:gosec // path validated by SanitizePath
	if err != nil {
		return nil
	}
	var cache cacheFile
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil
	}
	return &cache
}

// writeCache persists a check result to disk.
// Errors are silently ignored.
func (c *Checker) writeCache(result *cacheFile) {
	path := c.getCacheFilePath()
	if path == "" {
		return
	}
	// Validate the final path before writing to prevent path traversal (CWE-73)
	sanitizedPath, err := util.SanitizePath(path)
	if err != nil {
		return
	}
	dir := filepath.Dir(sanitizedPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	data, err := json.Marshal(result)
	if err != nil {
		return
	}
	_ = os.WriteFile(sanitizedPath, data, 0o600) //nolint:gosec // path validated by SanitizePath
}

// IsNewer returns true if latest is a newer version than current.
// Versions may optionally have a "v" prefix.
func IsNewer(current, latest string) bool {
	current = strings.TrimPrefix(current, "v")
	latest = strings.TrimPrefix(latest, "v")

	curParts := parseVersion(current)
	latParts := parseVersion(latest)

	if curParts == nil || latParts == nil {
		return false
	}

	for i := 0; i < 3; i++ {
		if latParts[i] > curParts[i] {
			return true
		}
		if latParts[i] < curParts[i] {
			return false
		}
	}
	return false
}

// parseVersion returns [major, minor, patch] or nil if invalid.
func parseVersion(v string) []int {
	// Strip any pre-release suffix (e.g., "-rc1")
	if idx := strings.IndexByte(v, '-'); idx >= 0 {
		v = v[:idx]
	}
	parts := strings.SplitN(v, ".", 3)
	if len(parts) != 3 {
		return nil
	}
	result := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil
		}
		result[i] = n
	}
	return result
}

// FormatNotification builds the user-facing notification string.
// The icon parameter should be passed from the caller (e.g., output.IconDependency)
// to allow proper color mode handling.
func FormatNotification(current, latest, icon string) string {
	styles := output.GetStyles()
	current = strings.TrimPrefix(current, "v")
	latest = strings.TrimPrefix(latest, "v")

	updateCmd := getUpdateCommand()

	label := styles.WarningText.Render(icon + " Update available:")
	versions := styles.Bold.Render(fmt.Sprintf("v%s → v%s", current, latest))

	msg := fmt.Sprintf("\n%s %s\n", label, versions)
	if updateCmd != "" {
		msg += fmt.Sprintf("   %s\n", styles.MutedText.Render(updateCmd))
	}
	return msg
}

// getUpdateCommand returns the appropriate update command for the current OS.
func getUpdateCommand() string {
	switch runtime.GOOS {
	case "darwin":
		return "brew upgrade armis-cli"
	case "linux":
		return "curl -sSL https://raw.githubusercontent.com/ArmisSecurity/armis-cli/main/scripts/install.sh | bash"
	case "windows":
		return "irm https://raw.githubusercontent.com/ArmisSecurity/armis-cli/main/scripts/install.ps1 | iex"
	default:
		return ""
	}
}
