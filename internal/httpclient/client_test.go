package httpclient

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	t.Run("uses default timeout when not specified", func(t *testing.T) {
		cfg := Config{}
		client := NewClient(cfg)

		if client.httpClient.Timeout != 30*time.Second {
			t.Errorf("Expected default timeout of 30s, got %v", client.httpClient.Timeout)
		}
	})

	t.Run("uses custom timeout", func(t *testing.T) {
		cfg := Config{
			Timeout: 60 * time.Second,
		}
		client := NewClient(cfg)

		if client.httpClient.Timeout != 60*time.Second {
			t.Errorf("Expected timeout of 60s, got %v", client.httpClient.Timeout)
		}
	})

	t.Run("disables timeout when requested", func(t *testing.T) {
		cfg := Config{
			DisableTimeout: true,
		}
		client := NewClient(cfg)

		if client.httpClient.Timeout != 0 {
			t.Errorf("Expected no timeout, got %v", client.httpClient.Timeout)
		}
	})

	t.Run("uses default retry settings", func(t *testing.T) {
		cfg := Config{}
		client := NewClient(cfg)

		if client.config.RetryMax != 3 {
			t.Errorf("Expected RetryMax of 3, got %d", client.config.RetryMax)
		}
		if client.config.RetryWaitMin != 1*time.Second {
			t.Errorf("Expected RetryWaitMin of 1s, got %v", client.config.RetryWaitMin)
		}
		if client.config.RetryWaitMax != 10*time.Second {
			t.Errorf("Expected RetryWaitMax of 10s, got %v", client.config.RetryWaitMax)
		}
	})
}

func TestClientDo_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	}))
	defer server.Close()

	client := NewClient(Config{
		Timeout: 5 * time.Second,
	})

	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test cleanup

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestClientDo_ClientError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad request"))
	}))
	defer server.Close()

	client := NewClient(Config{
		Timeout: 5 * time.Second,
	})

	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Expected no error for 4xx, got %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test cleanup

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", resp.StatusCode)
	}
}

func TestClientDo_ServerErrorRetry(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("server error"))
		} else {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("success"))
		}
	}))
	defer server.Close()

	client := NewClient(Config{
		RetryMax:     3,
		RetryWaitMin: 10 * time.Millisecond,
		RetryWaitMax: 50 * time.Millisecond,
		Timeout:      5 * time.Second,
	})

	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Expected success after retries, got error: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test cleanup

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	if attempts != 3 {
		t.Errorf("Expected 3 attempts, got %d", attempts)
	}
}

func TestClientDo_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(Config{
		Timeout: 5 * time.Second,
	})

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	cancel()

	_, err = client.Do(req)
	if err == nil {
		t.Error("Expected error due to context cancellation, got nil")
	}
}

func TestClientDo_PersistentServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("persistent error"))
	}))
	defer server.Close()

	client := NewClient(Config{
		RetryMax:     2,
		RetryWaitMin: 10 * time.Millisecond,
		RetryWaitMax: 50 * time.Millisecond,
		Timeout:      5 * time.Second,
	})

	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	_, err = client.Do(req)
	if err == nil {
		t.Error("Expected error after exhausting retries, got nil")
	}
}

func TestClientDo_RetryWithBody(t *testing.T) {
	const expectedBody = "test request body content"
	attempts := 0
	var receivedBodies []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		body, _ := io.ReadAll(r.Body)
		receivedBodies = append(receivedBodies, string(body))

		if attempts == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("service unavailable"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	}))
	defer server.Close()

	client := NewClient(Config{
		RetryMax:     3,
		RetryWaitMin: 10 * time.Millisecond,
		RetryWaitMax: 50 * time.Millisecond,
		Timeout:      5 * time.Second,
	})

	// Create request with body using bytes.NewReader which supports GetBody
	bodyReader := bytes.NewReader([]byte(expectedBody))
	req, err := http.NewRequest("POST", server.URL, bodyReader)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Set GetBody so the body can be regenerated for retries
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader([]byte(expectedBody))), nil
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Expected success after retry, got error: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test cleanup

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	if attempts != 2 {
		t.Errorf("Expected 2 attempts, got %d", attempts)
	}

	if len(receivedBodies) != 2 {
		t.Fatalf("Expected 2 received bodies, got %d", len(receivedBodies))
	}

	// Verify both attempts received the full body
	for i, body := range receivedBodies {
		if body != expectedBody {
			t.Errorf("Attempt %d: expected body %q, got %q", i+1, expectedBody, body)
		}
	}
}
