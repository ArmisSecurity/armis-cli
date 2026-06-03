package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPyPIGetPublishDate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/pypi/flask/json" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"releases": {
					"3.0.0": [{"upload_time_iso_8601": "2023-09-30T12:00:00Z"}],
					"2.3.3": [{"upload_time_iso_8601": "2023-08-15T10:00:00Z"}]
				}
			}`))
		}))
		defer server.Close()

		client := NewPyPIClientWithHTTP(server.Client(), server.URL)
		publishTime, err := client.GetPublishDate(context.Background(), "flask", "3.0.0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expected := time.Date(2023, 9, 30, 12, 0, 0, 0, time.UTC)
		if !publishTime.Equal(expected) {
			t.Errorf("expected %v, got %v", expected, publishTime)
		}
	})

	t.Run("package not found", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		client := NewPyPIClientWithHTTP(server.Client(), server.URL)
		_, err := client.GetPublishDate(context.Background(), "nonexistent-pkg", "1.0.0")
		if err == nil {
			t.Error("expected error for 404")
		}
	})

	t.Run("version not found", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"releases": {"1.0.0": [{"upload_time_iso_8601": "2023-01-01T00:00:00Z"}]}}`))
		}))
		defer server.Close()

		client := NewPyPIClientWithHTTP(server.Client(), server.URL)
		_, err := client.GetPublishDate(context.Background(), "flask", "99.99.99")
		if err == nil {
			t.Error("expected error for missing version")
		}
	})

	t.Run("invalid package name", func(t *testing.T) {
		client := NewPyPIClient()
		_, err := client.GetPublishDate(context.Background(), "../../../etc/passwd", "1.0.0")
		if err == nil {
			t.Error("expected error for invalid package name")
		}
	})

	t.Run("name normalization", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Normalized: Flask -> flask, my_package -> my-package
			if r.URL.Path != "/pypi/my-package/json" {
				t.Errorf("unexpected path: %s (expected normalized name)", r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"releases": {"1.0.0": [{"upload_time_iso_8601": "2023-01-01T00:00:00Z"}]}}`))
		}))
		defer server.Close()

		client := NewPyPIClientWithHTTP(server.Client(), server.URL)
		_, err := client.GetPublishDate(context.Background(), "My_Package", "1.0.0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("matches version under PEP 440 normalization", func(t *testing.T) {
		// Lockfile pins "2.0" but PyPI keys the release as "2.0.0" — the lookup
		// must still resolve via normalized comparison rather than reporting the
		// version as missing.
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"releases": {"2.0.0": [{"upload_time_iso_8601": "2023-01-01T00:00:00Z"}]}}`))
		}))
		defer server.Close()

		client := NewPyPIClientWithHTTP(server.Client(), server.URL)
		publishTime, err := client.GetPublishDate(context.Background(), "flask", "2.0")
		if err != nil {
			t.Fatalf("unexpected error resolving 2.0 against 2.0.0: %v", err)
		}
		expected := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
		if !publishTime.Equal(expected) {
			t.Errorf("expected %v, got %v", expected, publishTime)
		}
	})

	t.Run("nil http client defaults instead of panicking", func(t *testing.T) {
		// NewPyPIClientWithHTTP is exported, so a caller may pass nil. It must
		// default to a usable client rather than leave httpClient nil and panic
		// at httpClient.Do(). Asserting the field is populated keeps the test
		// hermetic (no real network call).
		client := NewPyPIClientWithHTTP(nil, "")
		if client.httpClient == nil {
			t.Fatal("expected a defaulted http client, got nil")
		}
		if client.baseURL != defaultPyPIURL {
			t.Errorf("expected baseURL to default to %q, got %q", defaultPyPIURL, client.baseURL)
		}
	})

	t.Run("caches responses", func(t *testing.T) {
		calls := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"releases": {"3.0.0": [{"upload_time_iso_8601": "2023-09-30T12:00:00Z"}], "2.3.3": [{"upload_time_iso_8601": "2023-08-15T10:00:00Z"}]}}`))
		}))
		defer server.Close()

		client := NewPyPIClientWithHTTP(server.Client(), server.URL)

		_, err := client.GetPublishDate(context.Background(), "flask", "3.0.0")
		if err != nil {
			t.Fatalf("first call: %v", err)
		}

		_, err = client.GetPublishDate(context.Background(), "flask", "2.3.3")
		if err != nil {
			t.Fatalf("second call: %v", err)
		}

		if calls != 1 {
			t.Errorf("expected 1 HTTP call (cached), got %d", calls)
		}
	})
}
