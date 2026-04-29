package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/httpclient"
	"github.com/ArmisSecurity/armis-cli/internal/testutil"
)

func TestClient_ReportAgentInventory(t *testing.T) {
	t.Parallel()

	t.Run("successful report", func(t *testing.T) {
		t.Parallel()
		var receivedPayload AgentInventoryPayload

		server := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("Expected POST, got %s", r.Method)
			}
			if r.URL.Path != "/api/v1/agents/inventory" {
				t.Errorf("Unexpected path: %s", r.URL.Path)
			}
			if r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("Expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
			}
			if !testutil.ContainsSubstring(r.Header.Get("Authorization"), "Basic ") {
				t.Error("Missing or invalid Authorization header")
			}

			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("Failed to read request body: %v", err)
			}
			if err := json.Unmarshal(body, &receivedPayload); err != nil {
				t.Fatalf("Failed to unmarshal request body: %v", err)
			}

			w.WriteHeader(http.StatusOK)
		})

		client := newTestClient(t, server.URL)
		version := "1.2.3"
		payload := AgentInventoryPayload{
			TenantID:    "tenant-1",
			MachineName: "host1",
			User:        "alice",
			Agents: []AgentInventoryEntry{
				{Name: "Cursor", Version: &version, ArmisMCPInstalled: true},
				{Name: "Aider", Version: nil, ArmisMCPInstalled: false},
			},
		}

		err := client.ReportAgentInventory(context.Background(), payload)
		if err != nil {
			t.Fatalf("ReportAgentInventory failed: %v", err)
		}

		if receivedPayload.TenantID != "tenant-1" {
			t.Errorf("TenantID = %q, want %q", receivedPayload.TenantID, "tenant-1")
		}
		if receivedPayload.MachineName != "host1" {
			t.Errorf("MachineName = %q, want %q", receivedPayload.MachineName, "host1")
		}
		if receivedPayload.User != "alice" {
			t.Errorf("User = %q, want %q", receivedPayload.User, "alice")
		}
		if len(receivedPayload.Agents) != 2 {
			t.Fatalf("len(Agents) = %d, want 2", len(receivedPayload.Agents))
		}
		if receivedPayload.Agents[0].Name != "Cursor" {
			t.Errorf("Agents[0].Name = %q, want %q", receivedPayload.Agents[0].Name, "Cursor")
		}
		if receivedPayload.Agents[0].Version == nil || *receivedPayload.Agents[0].Version != "1.2.3" {
			t.Errorf("Agents[0].Version = %v, want %q", receivedPayload.Agents[0].Version, "1.2.3")
		}
		if !receivedPayload.Agents[0].ArmisMCPInstalled {
			t.Error("Agents[0].ArmisMCPInstalled = false, want true")
		}
		if receivedPayload.Agents[1].Version != nil {
			t.Errorf("Agents[1].Version = %v, want nil", receivedPayload.Agents[1].Version)
		}
	})

	t.Run("empty agents array", func(t *testing.T) {
		t.Parallel()
		var receivedPayload AgentInventoryPayload

		server := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("Failed to read request body: %v", err)
			}
			if err := json.Unmarshal(body, &receivedPayload); err != nil {
				t.Fatalf("Failed to unmarshal request body: %v", err)
			}
			w.WriteHeader(http.StatusOK)
		})

		client := newTestClient(t, server.URL)
		payload := AgentInventoryPayload{
			MachineName: "host1",
			User:        "bob",
			Agents:      []AgentInventoryEntry{},
		}

		err := client.ReportAgentInventory(context.Background(), payload)
		if err != nil {
			t.Fatalf("ReportAgentInventory failed: %v", err)
		}
		if len(receivedPayload.Agents) != 0 {
			t.Errorf("len(Agents) = %d, want 0", len(receivedPayload.Agents))
		}
	})

	t.Run("API error", func(t *testing.T) {
		t.Parallel()
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			testutil.ErrorResponse(w, http.StatusUnauthorized, "invalid credentials")
		})

		client := newTestClient(t, server.URL)
		payload := AgentInventoryPayload{
			MachineName: "host1",
			User:        "alice",
			Agents:      []AgentInventoryEntry{},
		}

		err := client.ReportAgentInventory(context.Background(), payload)
		if err == nil {
			t.Fatal("Expected error, got nil")
		}
		apiErr, ok := err.(*APIError)
		if !ok {
			t.Fatalf("Expected *APIError, got %T", err)
		}
		if apiErr.StatusCode != http.StatusUnauthorized {
			t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, http.StatusUnauthorized)
		}
	})

	t.Run("empty tenant_id", func(t *testing.T) {
		t.Parallel()
		var receivedPayload AgentInventoryPayload

		server := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("Failed to read request body: %v", err)
			}
			if err := json.Unmarshal(body, &receivedPayload); err != nil {
				t.Fatalf("Failed to unmarshal request body: %v", err)
			}
			w.WriteHeader(http.StatusOK)
		})

		client := newTestClient(t, server.URL)
		payload := AgentInventoryPayload{
			TenantID:    "",
			MachineName: "host1",
			User:        "alice",
			Agents:      []AgentInventoryEntry{},
		}

		err := client.ReportAgentInventory(context.Background(), payload)
		if err != nil {
			t.Fatalf("ReportAgentInventory failed: %v", err)
		}
		if receivedPayload.TenantID != "" {
			t.Errorf("TenantID = %q, want empty string", receivedPayload.TenantID)
		}
	})
}

func newTestClient(t *testing.T, serverURL string) *Client {
	t.Helper()
	httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
	client, err := NewClient(serverURL, testutil.NewTestAuthProvider("token123"), false, 1*time.Minute,
		WithHTTPClient(httpClient))
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	return client
}
