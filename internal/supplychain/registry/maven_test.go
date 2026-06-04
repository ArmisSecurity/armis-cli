package registry

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMavenGetPublishDate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		// 2023-09-30T12:00:00Z in milliseconds since epoch.
		ts := time.Date(2023, 9, 30, 12, 0, 0, 0, time.UTC).UnixMilli()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/solrsearch/select" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			q := r.URL.Query().Get("q")
			if !strings.Contains(q, `g:"org.springframework"`) || !strings.Contains(q, `a:"spring-core"`) {
				t.Errorf("unexpected query: %s", q)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"response":{"docs":[{"timestamp":%d}]}}`, ts)
		}))
		defer server.Close()

		client := NewMavenClientWithHTTP(server.Client(), server.URL)
		publishTime, err := client.GetPublishDate(context.Background(), "org.springframework:spring-core", "6.0.0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expected := time.UnixMilli(ts)
		if !publishTime.Equal(expected) {
			t.Errorf("expected %v, got %v", expected, publishTime)
		}
	})

	t.Run("invalid coordinate without colon", func(t *testing.T) {
		client := NewMavenClient()
		_, err := client.GetPublishDate(context.Background(), "not-a-coordinate", "1.0.0")
		if err == nil {
			t.Error("expected error for coordinate missing group:artifact separator")
		}
	})

	t.Run("invalid groupId characters", func(t *testing.T) {
		client := NewMavenClient()
		_, err := client.GetPublishDate(context.Background(), `org.evil"/../:spring-core`, "1.0.0")
		if err == nil {
			t.Error("expected error for invalid groupId characters")
		}
	})

	t.Run("artifact not found", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"response":{"docs":[]}}`))
		}))
		defer server.Close()

		client := NewMavenClientWithHTTP(server.Client(), server.URL)
		_, err := client.GetPublishDate(context.Background(), "com.example:missing", "1.0.0")
		if err == nil {
			t.Error("expected error for empty docs")
		}
	})

	t.Run("non-200 status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client := NewMavenClientWithHTTP(server.Client(), server.URL)
		_, err := client.GetPublishDate(context.Background(), "com.example:lib", "1.0.0")
		if err == nil {
			t.Error("expected error for 500 status")
		}
	})

	t.Run("escapes solr query special characters in version", func(t *testing.T) {
		ts := time.Date(2020, 5, 5, 0, 0, 0, 0, time.UTC).UnixMilli()
		var gotQuery string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotQuery = r.URL.Query().Get("q")
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"response":{"docs":[{"timestamp":%d}]}}`, ts)
		}))
		defer server.Close()

		client := NewMavenClientWithHTTP(server.Client(), server.URL)
		// A version containing a quote and backslash would, unescaped, break out
		// of the quoted Solr term. After escaping, the decoded query must keep the
		// value contained inside v:"..." with both characters backslash-escaped.
		if _, err := client.GetPublishDate(context.Background(), "com.example:lib", `1.0"\inject`); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if want := `v:"1.0\"\\inject"`; !strings.Contains(gotQuery, want) {
			t.Errorf("expected escaped version term %q in query, got %q", want, gotQuery)
		}
	})

	t.Run("cached result is reused", func(t *testing.T) {
		ts := time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
		var calls int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"response":{"docs":[{"timestamp":%d}]}}`, ts)
		}))
		defer server.Close()

		client := NewMavenClientWithHTTP(server.Client(), server.URL)
		for i := 0; i < 3; i++ {
			if _, err := client.GetPublishDate(context.Background(), "com.example:cached", "1.0.0"); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		}
		if calls != 1 {
			t.Errorf("expected 1 upstream call (rest cached), got %d", calls)
		}
	})
}

func TestMavenGetPublishDates(t *testing.T) {
	ts := time.Date(2021, 6, 15, 0, 0, 0, 0, time.UTC).UnixMilli()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"response":{"docs":[{"timestamp":%d}]}}`, ts)
	}))
	defer server.Close()

	client := NewMavenClientWithHTTP(server.Client(), server.URL)
	packages := []PackageRequest{
		{Name: "org.springframework:spring-core", Version: "6.0.0"},
		{Name: "com.google.guava:guava", Version: "32.0.0"},
	}
	results := client.GetPublishDates(context.Background(), packages)

	if len(results) != len(packages) {
		t.Fatalf("expected %d results, got %d", len(packages), len(results))
	}
	for i, r := range results {
		if r.Err != nil {
			t.Errorf("result %d: unexpected error: %v", i, r.Err)
		}
		if r.Name != packages[i].Name {
			t.Errorf("result %d: expected name %q, got %q", i, packages[i].Name, r.Name)
		}
	}
}
