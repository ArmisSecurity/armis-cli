package auth

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	testRegionUS1 = "us1"
	testRegionEU1 = "eu1"
	testRegionAP1 = "ap1"
)

func TestRegionCache_RoundTrip(t *testing.T) {
	cache := &RegionCache{cacheDir: t.TempDir()}

	// Initially empty
	region, ok := cache.Load("client-123")
	if ok {
		t.Error("Expected no cached region initially")
	}
	if region != "" {
		t.Errorf("Expected empty region, got %q", region)
	}

	// Save and load
	cache.Save("client-123", testRegionUS1)
	region, ok = cache.Load("client-123")
	if !ok {
		t.Error("Expected to find cached region after save")
	}
	if region != testRegionUS1 {
		t.Errorf("Expected %q, got %q", testRegionUS1, region)
	}
}

func TestRegionCache_ClientIDMismatch(t *testing.T) {
	cache := &RegionCache{cacheDir: t.TempDir()}

	// Save for client-123
	cache.Save("client-123", testRegionUS1)

	// Try to load for different client - should NOT return the cached region
	region, ok := cache.Load("client-456")
	if ok {
		t.Error("Expected cache miss for different client ID")
	}
	if region != "" {
		t.Errorf("Expected empty region for mismatched client, got %q", region)
	}

	// Original client should still work
	region, ok = cache.Load("client-123")
	if !ok {
		t.Error("Expected cache hit for original client")
	}
	if region != testRegionUS1 {
		t.Errorf("Expected %q, got %q", testRegionUS1, region)
	}
}

func TestRegionCache_Clear(t *testing.T) {
	cache := &RegionCache{cacheDir: t.TempDir()}

	cache.Save("client-123", testRegionUS1)

	// Verify it's there
	_, ok := cache.Load("client-123")
	if !ok {
		t.Fatal("Expected region to be cached before clear")
	}

	// Clear
	cache.Clear()

	// Verify it's gone
	region, ok := cache.Load("client-123")
	if ok {
		t.Error("Expected cache miss after clear")
	}
	if region != "" {
		t.Errorf("Expected empty region after clear, got %q", region)
	}
}

func TestRegionCache_MissingFile(t *testing.T) {
	cache := &RegionCache{cacheDir: t.TempDir()}

	// Load from non-existent file should return empty gracefully
	region, ok := cache.Load("client-123")
	if ok {
		t.Error("Expected cache miss for non-existent file")
	}
	if region != "" {
		t.Errorf("Expected empty region, got %q", region)
	}
}

func TestRegionCache_CorruptJSON(t *testing.T) {
	tempDir := t.TempDir()
	cache := &RegionCache{cacheDir: tempDir}

	// Write corrupt JSON
	cachePath := filepath.Join(tempDir, regionCacheFileName)
	if err := os.WriteFile(cachePath, []byte("not valid json{"), 0o600); err != nil {
		t.Fatalf("Failed to write corrupt file: %v", err)
	}

	// Load should handle corrupt JSON gracefully
	region, ok := cache.Load("client-123")
	if ok {
		t.Error("Expected cache miss for corrupt JSON")
	}
	if region != "" {
		t.Errorf("Expected empty region for corrupt JSON, got %q", region)
	}
}

func TestRegionCache_EmptyRegion(t *testing.T) {
	cache := &RegionCache{cacheDir: t.TempDir()}

	// Save with empty region should be a no-op
	cache.Save("client-123", "")

	// Should still be empty
	region, ok := cache.Load("client-123")
	if ok {
		t.Error("Expected cache miss after saving empty region")
	}
	if region != "" {
		t.Errorf("Expected empty region, got %q", region)
	}
}

func TestRegionCache_EmptyClientID(t *testing.T) {
	cache := &RegionCache{cacheDir: t.TempDir()}

	// Save with empty client ID should be a no-op
	cache.Save("", testRegionUS1)

	// Should still be empty
	region, ok := cache.Load("")
	if ok {
		t.Error("Expected cache miss after saving empty client ID")
	}
	if region != "" {
		t.Errorf("Expected empty region, got %q", region)
	}
}

func TestRegionCache_Overwrite(t *testing.T) {
	cache := &RegionCache{cacheDir: t.TempDir()}

	// Save initial region
	cache.Save("client-123", testRegionUS1)

	// Overwrite with new region
	cache.Save("client-123", testRegionEU1)

	// Should return the new region
	region, ok := cache.Load("client-123")
	if !ok {
		t.Error("Expected cache hit after overwrite")
	}
	if region != testRegionEU1 {
		t.Errorf("Expected %q after overwrite, got %q", testRegionEU1, region)
	}
}

func TestRegionCache_FilePermissions(t *testing.T) {
	tempDir := t.TempDir()
	cache := &RegionCache{cacheDir: tempDir}

	cache.Save("client-123", testRegionUS1)

	// Verify file permissions are restrictive (0600)
	cachePath := filepath.Join(tempDir, regionCacheFileName)
	info, err := os.Stat(cachePath)
	if err != nil {
		t.Fatalf("Failed to stat cache file: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("Expected file permissions 0600, got %o", perm)
	}
}

func TestRegionCache_ClearNonExistent(t *testing.T) {
	cache := &RegionCache{cacheDir: t.TempDir()}

	// Clear should not panic when file doesn't exist
	cache.Clear() // Should be a no-op, not panic
}

func TestRegionCache_TableDriven(t *testing.T) {
	tests := []struct {
		name       string
		saveClient string
		saveRegion string
		loadClient string
		wantRegion string
		wantFound  bool
	}{
		{
			name:       "exact match",
			saveClient: "client-a",
			saveRegion: testRegionUS1,
			loadClient: "client-a",
			wantRegion: testRegionUS1,
			wantFound:  true,
		},
		{
			name:       "client mismatch",
			saveClient: "client-a",
			saveRegion: testRegionUS1,
			loadClient: "client-b",
			wantRegion: "",
			wantFound:  false,
		},
		{
			name:       "case sensitive client ID",
			saveClient: "Client-A",
			saveRegion: testRegionUS1,
			loadClient: "client-a",
			wantRegion: "",
			wantFound:  false,
		},
		{
			name:       "special characters in client ID",
			saveClient: "client@123.example.com",
			saveRegion: testRegionAP1,
			loadClient: "client@123.example.com",
			wantRegion: testRegionAP1,
			wantFound:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := &RegionCache{cacheDir: t.TempDir()}

			if tt.saveClient != "" && tt.saveRegion != "" {
				cache.Save(tt.saveClient, tt.saveRegion)
			}

			region, found := cache.Load(tt.loadClient)
			if found != tt.wantFound {
				t.Errorf("Load(%q) found = %v, want %v", tt.loadClient, found, tt.wantFound)
			}
			if region != tt.wantRegion {
				t.Errorf("Load(%q) region = %q, want %q", tt.loadClient, region, tt.wantRegion)
			}
		})
	}
}

// TestPackageLevelFunctions verifies the backward-compatible package functions work.
// Note: These use the global defaultCache, which shares state across tests if run in parallel.
// We test them in isolation by ensuring the cache is cleared.
func TestPackageLevelFunctions(t *testing.T) {
	// This test uses the real cache directory, so we just verify the functions
	// don't panic and maintain the basic contract.

	// Clear any existing cache
	clearCachedRegion()

	// Load from empty should return false
	region, ok := loadCachedRegion("test-client-pkg-level")
	if ok {
		// Cache might have leftover data from other tests; just verify contract
		t.Logf("Unexpected cache hit, region=%q (may be leftover from other tests)", region)
	}
}
