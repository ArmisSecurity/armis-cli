// Package auth provides authentication for the Armis API.
// This file handles region caching to avoid auto-discovery on subsequent authentications.
package auth

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/ArmisSecurity/armis-cli/internal/util"
)

const (
	// regionCacheFileName is the name of the region cache file.
	regionCacheFileName = "region-cache.json"
)

// regionCacheEntry is the on-disk JSON structure for persisting region.
type regionCacheEntry struct {
	ClientID string `json:"client_id"`
	Region   string `json:"region"`
}

// RegionCache handles region caching with optional directory override for testing.
type RegionCache struct {
	cacheDir string // for testing; empty means use util.GetCacheDir()
}

// NewRegionCache creates a region cache with default settings.
func NewRegionCache() *RegionCache {
	return &RegionCache{}
}

// Load attempts to load a cached region for the given client ID.
// Returns the region and true if found, empty string and false otherwise.
func (c *RegionCache) Load(clientID string) (string, bool) {
	path := c.getFilePath()
	if path == "" {
		return "", false
	}

	data, err := os.ReadFile(path) //nolint:gosec // path validated by getFilePath
	if err != nil {
		return "", false
	}

	var cache regionCacheEntry
	if err := json.Unmarshal(data, &cache); err != nil {
		return "", false
	}

	// Only return if client ID matches (prevent cross-credential pollution)
	if cache.ClientID != clientID {
		return "", false
	}

	return cache.Region, cache.Region != ""
}

// Save persists the region for the given client ID.
// Errors are silently ignored (best-effort caching).
func (c *RegionCache) Save(clientID, region string) {
	if clientID == "" || region == "" {
		return
	}

	path := c.getFilePath()
	if path == "" {
		return
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}

	cache := regionCacheEntry{
		ClientID: clientID,
		Region:   region,
	}

	data, err := json.Marshal(cache)
	if err != nil {
		return
	}

	_ = os.WriteFile(path, data, 0o600) //nolint:gosec // path validated by getFilePath
}

// Clear removes the cached region.
// Used when authentication fails with a cached region hint.
func (c *RegionCache) Clear() {
	path := c.getFilePath()
	if path == "" {
		return
	}

	_ = os.Remove(path) //nolint:errcheck // best-effort cleanup
}

// getFilePath returns the validated path to the region cache file.
func (c *RegionCache) getFilePath() string {
	if c.cacheDir != "" {
		// Testing override - validate the provided path
		sanitized, err := util.SanitizePath(c.cacheDir)
		if err != nil {
			return ""
		}
		return filepath.Join(sanitized, regionCacheFileName)
	}
	return util.GetCacheFilePath(regionCacheFileName)
}

// Package-level convenience functions using a default cache instance.
// These maintain backward compatibility with existing code.

var defaultCache = NewRegionCache()

func loadCachedRegion(clientID string) (string, bool) {
	return defaultCache.Load(clientID)
}

func saveCachedRegion(clientID, region string) {
	defaultCache.Save(clientID, region)
}

func clearCachedRegion() {
	defaultCache.Clear()
}
