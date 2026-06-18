package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestGetPublishDate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/express" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"time":{"4.18.2":"2022-10-08T14:21:24.484Z","4.18.1":"2022-04-29T14:00:00.000Z"}}`))
		}))
		defer server.Close()

		client := NewClientWithHTTP(server.Client(), server.URL)
		publishTime, err := client.GetPublishDate(context.Background(), "express", "4.18.2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expected := time.Date(2022, 10, 8, 14, 21, 24, 484000000, time.UTC)
		if !publishTime.Equal(expected) {
			t.Errorf("expected %v, got %v", expected, publishTime)
		}
	})

	t.Run("scoped package URL encoding", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// url.PathEscape encodes @types/node as %40types%2Fnode
			// httptest server receives the raw (decoded) path
			if r.URL.RawPath != "/%40types%2Fnode" && r.URL.Path != "/@types/node" {
				t.Errorf("unexpected path: raw=%s path=%s", r.URL.RawPath, r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"time":{"20.10.0":"2023-11-20T10:00:00.000Z"}}`))
		}))
		defer server.Close()

		client := NewClientWithHTTP(server.Client(), server.URL)
		_, err := client.GetPublishDate(context.Background(), "@types/node", "20.10.0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("package not found", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		client := NewClientWithHTTP(server.Client(), server.URL)
		_, err := client.GetPublishDate(context.Background(), "nonexistent-pkg", "1.0.0")
		if err == nil {
			t.Error("expected error for 404")
		}
	})

	t.Run("version not in metadata", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"time":{"1.0.0":"2023-01-01T00:00:00.000Z"}}`))
		}))
		defer server.Close()

		client := NewClientWithHTTP(server.Client(), server.URL)
		_, err := client.GetPublishDate(context.Background(), "express", "99.99.99")
		if err == nil {
			t.Error("expected error for missing version")
		}
	})

	t.Run("time map with unpublished object", func(t *testing.T) {
		// npm includes non-date keys in "time" whose values are objects, not
		// strings — most commonly "unpublished": {"time":"...","versions":[...]}
		// on any package that ever unpublished a version. The whole "time" map
		// must still parse (json.RawMessage), and the requested version's date
		// must decode correctly rather than the object aborting the parse and
		// losing every version's publish date.
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"time":{` +
				`"created":"2025-12-04T21:32:57.747Z",` +
				`"modified":"2025-12-09T03:31:24.890Z",` +
				`"99.99.1":"2025-12-04T21:33:00.000Z",` +
				`"99.99.2":"2025-12-05T10:00:00.000Z",` +
				`"unpublished":{"time":"2025-12-09T03:31:24.890Z","versions":[]}}}`))
		}))
		defer server.Close()

		client := NewClientWithHTTP(server.Client(), server.URL)
		publishTime, err := client.GetPublishDate(context.Background(), "path-to-regexp-updated", "99.99.1")
		if err != nil {
			t.Fatalf("unpublished object must not break parsing: %v", err)
		}
		expected := time.Date(2025, 12, 4, 21, 33, 0, 0, time.UTC)
		if !publishTime.Equal(expected) {
			t.Errorf("expected %v, got %v", expected, publishTime)
		}
	})

	t.Run("invalid package name", func(t *testing.T) {
		client := NewClient()
		_, err := client.GetPublishDate(context.Background(), "../../../etc/passwd", "1.0.0")
		if err == nil {
			t.Error("expected error for invalid package name")
		}
	})

	t.Run("rate limit (429)", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		defer server.Close()

		client := NewClientWithHTTP(server.Client(), server.URL)
		_, err := client.GetPublishDate(context.Background(), "express", "4.18.2")
		if err == nil {
			t.Error("expected error for 429")
		}
	})

	t.Run("response too large", func(t *testing.T) {
		// A registry body larger than maxResponseSize must fail with a clear
		// "too large" error rather than being silently truncated by LimitReader
		// and surfacing as a confusing JSON parse error.
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			filler := make([]byte, maxResponseSize+1)
			for i := range filler {
				filler[i] = 'a'
			}
			_, _ = w.Write(filler)
		}))
		defer server.Close()

		client := NewClientWithHTTP(server.Client(), server.URL)
		_, err := client.GetPublishDate(context.Background(), "express", "4.18.2")
		if err == nil {
			t.Fatal("expected error for oversized response")
		}
		if !strings.Contains(err.Error(), "too large") {
			t.Fatalf("expected 'too large' error, got: %v", err)
		}
	})

	t.Run("caches responses", func(t *testing.T) {
		calls := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"time":{"4.18.2":"2022-10-08T14:21:24.484Z","4.18.1":"2022-04-29T14:00:00.000Z"}}`))
		}))
		defer server.Close()

		client := NewClientWithHTTP(server.Client(), server.URL)

		_, err := client.GetPublishDate(context.Background(), "express", "4.18.2")
		if err != nil {
			t.Fatalf("first call: %v", err)
		}

		_, err = client.GetPublishDate(context.Background(), "express", "4.18.1")
		if err != nil {
			t.Fatalf("second call: %v", err)
		}

		if calls != 1 {
			t.Errorf("expected 1 HTTP call (cached), got %d", calls)
		}
	})
}

func TestGetPublishDates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/express":
			_, _ = w.Write([]byte(`{"time":{"4.18.2":"2022-10-08T14:21:24.484Z"}}`))
		case "/lodash":
			_, _ = w.Write([]byte(`{"time":{"4.17.21":"2021-02-20T00:00:00.000Z"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	packages := []PackageRequest{
		{"express", "4.18.2"},
		{"lodash", "4.17.21"},
		{"nonexistent", "1.0.0"},
	}

	results := client.GetPublishDates(context.Background(), packages)
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	if results[0].Err != nil {
		t.Errorf("express: unexpected error: %v", results[0].Err)
	}
	if results[1].Err != nil {
		t.Errorf("lodash: unexpected error: %v", results[1].Err)
	}
	if results[2].Err == nil {
		t.Error("nonexistent: expected error")
	}
}

// TestCacheBounded verifies the metadata memo stops growing at maxCacheEntries
// so a reused client cannot leak memory without bound (CWE-770). Rather than
// drive 10k real fetches, this white-box test seeds cacheLen at the cap and
// confirms a subsequent successful fetch is not stored — the request still
// succeeds (correctness must not depend on the cache), it just isn't memoized.
func TestCacheBounded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"time":{"1.0.0":"2020-01-01T00:00:00.000Z"}}`))
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	client.cacheLen.Store(maxCacheEntries) // pretend the cache is already full

	if _, err := client.GetPublishDate(context.Background(), "freshpkg", "1.0.0"); err != nil {
		t.Fatalf("fetch must still succeed when cache is full: %v", err)
	}

	if _, ok := client.cache.Load("freshpkg"); ok {
		t.Error("entry must not be stored once the cache is at capacity")
	}
	if got := client.cacheLen.Load(); got != maxCacheEntries {
		t.Errorf("cacheLen must not grow past the cap, got %d want %d", got, maxCacheEntries)
	}
}

// TestCacheCountsDistinctEntries confirms cacheLen tracks the number of stored
// keys so the bound in fetchMetadata is meaningful: two distinct packages add
// two entries, and re-fetching an already-cached name does not double-count.
func TestCacheCountsDistinctEntries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"time":{"1.0.0":"2020-01-01T00:00:00.000Z"}}`))
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)

	for i := 0; i < 3; i++ {
		name := "pkg" + strconv.Itoa(i)
		if _, err := client.GetPublishDate(context.Background(), name, "1.0.0"); err != nil {
			t.Fatalf("fetch %s: %v", name, err)
		}
	}
	// Re-fetch an existing name: served from cache, must not increment the count.
	if _, err := client.GetPublishDate(context.Background(), "pkg0", "1.0.0"); err != nil {
		t.Fatalf("re-fetch pkg0: %v", err)
	}

	if got := client.cacheLen.Load(); got != 3 {
		t.Errorf("cacheLen = %d, want 3 (one per distinct package, no double-count)", got)
	}
}
