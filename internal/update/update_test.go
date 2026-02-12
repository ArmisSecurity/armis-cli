package update

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testLatestVersion = "v1.2.0"

func TestIsNewer(t *testing.T) {
	tests := []struct {
		name     string
		current  string
		latest   string
		expected bool
	}{
		{"newer major", "1.0.0", "2.0.0", true},
		{"newer minor", "1.0.0", "1.1.0", true},
		{"newer patch", "1.0.0", "1.0.1", true},
		{"same version", "1.0.7", "1.0.7", false},
		{"older major", "2.0.0", "1.0.0", false},
		{"older minor", "1.2.0", "1.1.0", false},
		{"older patch", "1.0.2", "1.0.1", false},
		{"with v prefix current", "v1.0.0", "1.1.0", true},
		{"with v prefix latest", "1.0.0", "v1.1.0", true},
		{"with v prefix both", "v1.0.0", "v1.1.0", true},
		{"pre-release stripped", "1.0.0", "1.1.0-rc1", true},
		{"pre-release current", "1.0.0-rc1", "1.0.0", false},
		{"dev current", "dev", "1.0.0", false},
		{"invalid current", "not-a-version", "1.0.0", false},
		{"invalid latest", "1.0.0", "not-a-version", false},
		{"empty current", "", "1.0.0", false},
		{"empty latest", "1.0.0", "", false},
		{"empty both", "", "", false},
		{"two part version", "1.0", "1.0.1", false},
		{"four part version", "1.0.0.0", "1.0.1", false},
		{"negative numbers", "1.0.0", "-1.0.0", false},
		{"large numbers", "1.0.7", "1.0.100", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsNewer(tt.current, tt.latest)
			if result != tt.expected {
				t.Errorf("IsNewer(%q, %q) = %v, want %v",
					tt.current, tt.latest, result, tt.expected)
			}
		})
	}
}

func TestParseVersion(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected []int
	}{
		{"valid version", "1.2.3", []int{1, 2, 3}},
		{"with pre-release", "1.2.3-rc1", []int{1, 2, 3}},
		{"zeros", "0.0.0", []int{0, 0, 0}},
		{"large numbers", "10.20.30", []int{10, 20, 30}},
		{"two parts", "1.2", nil},
		{"one part", "1", nil},
		{"empty", "", nil},
		{"non-numeric", "a.b.c", nil},
		{"mixed", "1.b.3", nil},
		{"negative", "-1.0.0", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseVersion(tt.version)
			if tt.expected == nil {
				if result != nil {
					t.Errorf("parseVersion(%q) = %v, want nil", tt.version, result)
				}
				return
			}
			if result == nil {
				t.Errorf("parseVersion(%q) = nil, want %v", tt.version, tt.expected)
				return
			}
			for i := 0; i < 3; i++ {
				if result[i] != tt.expected[i] {
					t.Errorf("parseVersion(%q)[%d] = %d, want %d",
						tt.version, i, result[i], tt.expected[i])
				}
			}
		})
	}
}

func TestFormatNotification(t *testing.T) {
	result := FormatNotification("1.0.0", "1.1.0")

	if result == "" {
		t.Error("FormatNotification returned empty string")
	}

	// Check that it contains the version numbers
	if !strings.Contains(result, "v1.1.0") {
		t.Errorf("notification should contain latest version, got: %s", result)
	}
	if !strings.Contains(result, "v1.0.0") {
		t.Errorf("notification should contain current version, got: %s", result)
	}

	// Check with v prefix
	result = FormatNotification("v1.0.0", "v1.1.0")
	if !strings.Contains(result, "v1.1.0") {
		t.Errorf("notification should normalize version, got: %s", result)
	}
}

func TestChecker_FetchLatestVersion(t *testing.T) {
	tests := []struct {
		name         string
		responseCode int
		responseBody string
		expectedTag  string
		expectError  bool
	}{
		{
			name:         "success",
			responseCode: http.StatusOK,
			responseBody: `{"tag_name": "` + testLatestVersion + `"}`,
			expectedTag:  testLatestVersion,
			expectError:  false,
		},
		{
			name:         "not found",
			responseCode: http.StatusNotFound,
			responseBody: `{"message": "Not Found"}`,
			expectedTag:  "",
			expectError:  true,
		},
		{
			name:         "rate limited",
			responseCode: http.StatusForbidden,
			responseBody: `{"message": "API rate limit exceeded"}`,
			expectedTag:  "",
			expectError:  true,
		},
		{
			name:         "invalid json",
			responseCode: http.StatusOK,
			responseBody: `not json`,
			expectedTag:  "",
			expectError:  true,
		},
		{
			name:         "empty tag",
			responseCode: http.StatusOK,
			responseBody: `{"tag_name": ""}`,
			expectedTag:  "",
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify headers
				if r.Header.Get("Accept") != "application/vnd.github.v3+json" {
					t.Error("missing Accept header")
				}
				if r.Header.Get("User-Agent") != "armis-cli-update-check" {
					t.Error("missing User-Agent header")
				}

				w.WriteHeader(tt.responseCode)
				_, _ = w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			checker := NewChecker("1.0.0")
			checker.githubAPIURL = server.URL

			tag, err := checker.fetchLatestVersion(context.Background())

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if tag != tt.expectedTag {
					t.Errorf("tag = %q, want %q", tag, tt.expectedTag)
				}
			}
		})
	}
}

func TestChecker_CacheReadWrite(t *testing.T) {
	cacheDir := t.TempDir()

	checker := NewChecker("1.0.0")
	checker.cacheDir = cacheDir

	// Initially no cache
	cached := checker.readCache()
	if cached != nil {
		t.Error("expected nil cache initially")
	}

	// Write cache
	now := time.Now()
	checker.writeCache(&cacheFile{
		LatestVersion: "v1.2.0",
		CheckedAt:     now,
	})

	// Read it back
	cached = checker.readCache()
	if cached == nil {
		t.Fatal("expected non-nil cache after write")
		return
	}
	if cached.LatestVersion != testLatestVersion {
		t.Errorf("LatestVersion = %q, want %q", cached.LatestVersion, "v1.2.0")
	}

	// Verify file was created
	path := filepath.Join(cacheDir, cacheFileName)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("cache file was not created")
	}
}

func TestChecker_CacheExpiry(t *testing.T) {
	cacheDir := t.TempDir()

	// Create a mock server that returns v2.0.0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"tag_name": "v2.0.0"}`))
	}))
	defer server.Close()

	checker := NewChecker("1.0.0")
	checker.cacheDir = cacheDir
	checker.githubAPIURL = server.URL
	checker.cacheTTL = time.Hour // 1 hour TTL

	// Write an old cache entry
	oldTime := time.Now().Add(-2 * time.Hour) // 2 hours ago
	checker.writeCache(&cacheFile{
		LatestVersion: "v1.5.0",
		CheckedAt:     oldTime,
	})

	// Check should fetch fresh because cache is expired
	result := checker.check(context.Background())
	if result == nil {
		t.Fatal("expected non-nil result")
		return
	}
	if result.LatestVersion != "v2.0.0" {
		t.Errorf("LatestVersion = %q, want %q (should have fetched fresh)", result.LatestVersion, "v2.0.0")
	}
}

func TestChecker_CacheFresh(t *testing.T) {
	cacheDir := t.TempDir()

	// Create a mock server that should NOT be called
	serverCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"tag_name": "v2.0.0"}`))
	}))
	defer server.Close()

	checker := NewChecker("1.0.0")
	checker.cacheDir = cacheDir
	checker.githubAPIURL = server.URL
	checker.cacheTTL = time.Hour

	// Write a fresh cache entry
	checker.writeCache(&cacheFile{
		LatestVersion: "v1.5.0",
		CheckedAt:     time.Now(), // fresh
	})

	// Check should use cache
	result := checker.check(context.Background())
	if result == nil {
		t.Fatal("expected non-nil result")
		return
	}
	if result.LatestVersion != "v1.5.0" {
		t.Errorf("LatestVersion = %q, want %q (should have used cache)", result.LatestVersion, "v1.5.0")
	}
	if serverCalled {
		t.Error("server should not have been called when cache is fresh")
	}
}

func TestChecker_NetworkFailure(t *testing.T) {
	cacheDir := t.TempDir()

	checker := NewChecker("1.0.0")
	checker.cacheDir = cacheDir
	checker.githubAPIURL = "http://localhost:1" // invalid port

	// Should not panic, should return nil
	result := checker.check(context.Background())
	if result != nil {
		t.Error("expected nil result on network failure")
	}
}

func TestChecker_CheckInBackground(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"tag_name": "` + testLatestVersion + `"}`))
	}))
	defer server.Close()

	checker := NewChecker("1.0.0")
	checker.cacheDir = t.TempDir()
	checker.githubAPIURL = server.URL

	ctx := context.Background()
	ch := checker.CheckInBackground(ctx)

	// Should receive a result
	select {
	case result, ok := <-ch:
		if !ok {
			t.Error("channel closed without result")
		}
		if result == nil {
			t.Error("expected non-nil result")
		} else if result.LatestVersion != testLatestVersion {
			t.Errorf("LatestVersion = %q, want %q", result.LatestVersion, "v1.2.0")
		}
	case <-time.After(5 * time.Second):
		t.Error("timed out waiting for result")
	}

	// Channel should be closed
	select {
	case _, ok := <-ch:
		if ok {
			t.Error("expected channel to be closed")
		}
	case <-time.After(time.Second):
		t.Error("channel not closed")
	}
}

func TestChecker_NoUpdateNeeded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"tag_name": "v1.0.0"}`))
	}))
	defer server.Close()

	checker := NewChecker("1.0.0") // same version
	checker.cacheDir = t.TempDir()
	checker.githubAPIURL = server.URL

	result := checker.check(context.Background())
	if result != nil {
		t.Error("expected nil result when no update is needed")
	}
}

func TestChecker_NoCacheDir(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"tag_name": "` + testLatestVersion + `"}`))
	}))
	defer server.Close()

	checker := NewChecker("1.0.0")
	checker.cacheDir = "/nonexistent/path/that/cannot/be/created/\x00"
	checker.githubAPIURL = server.URL

	// Should still work, just without caching
	result := checker.check(context.Background())
	if result == nil {
		t.Error("expected non-nil result even without cache")
	}
}

func TestChecker_CorruptCache(t *testing.T) {
	cacheDir := t.TempDir()

	// Write corrupt cache file
	cachePath := filepath.Join(cacheDir, cacheFileName)
	err := os.WriteFile(cachePath, []byte("not valid json"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"tag_name": "` + testLatestVersion + `"}`))
	}))
	defer server.Close()

	checker := NewChecker("1.0.0")
	checker.cacheDir = cacheDir
	checker.githubAPIURL = server.URL

	// Should fetch fresh due to corrupt cache
	result := checker.check(context.Background())
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.LatestVersion != testLatestVersion {
		t.Errorf("LatestVersion = %q, want %q", result.LatestVersion, "v1.2.0")
	}
}

func TestGetUpdateCommand(t *testing.T) {
	// Just verify it returns something (actual value depends on runtime.GOOS)
	cmd := getUpdateCommand()
	// We can't easily test platform-specific behavior, but we can ensure it doesn't panic
	_ = cmd
}

func TestNewChecker(t *testing.T) {
	checker := NewChecker("1.0.7")
	if checker.currentVersion != "1.0.7" {
		t.Errorf("currentVersion = %q, want %q", checker.currentVersion, "1.0.7")
	}
	if checker.githubAPIURL != githubReleasesURL {
		t.Errorf("githubAPIURL = %q, want %q", checker.githubAPIURL, githubReleasesURL)
	}
	if checker.cacheTTL != cacheTTL {
		t.Errorf("cacheTTL = %v, want %v", checker.cacheTTL, cacheTTL)
	}
	if checker.httpClient == nil {
		t.Error("httpClient should not be nil")
	}
}

func TestCacheFileJSON(t *testing.T) {
	// Test that cacheFile serializes/deserializes correctly
	original := &cacheFile{
		LatestVersion: "v1.2.3",
		CheckedAt:     time.Now().UTC().Truncate(time.Second),
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded cacheFile
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.LatestVersion != original.LatestVersion {
		t.Errorf("LatestVersion = %q, want %q", decoded.LatestVersion, original.LatestVersion)
	}
}
