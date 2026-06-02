package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
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
