package cmd

import (
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/agentdetect"
	"github.com/ArmisSecurity/armis-cli/internal/api"
)

func TestBuildInventoryPayload(t *testing.T) {
	t.Parallel()

	t.Run("with agents", func(t *testing.T) {
		t.Parallel()
		userResult := agentdetect.UserResult{
			User: "alice",
			Agents: []agentdetect.DetectedAgent{
				{Name: "Cursor", MCPInstalled: true, Version: "1.2.3", User: "alice"},
				{Name: "Aider", MCPInstalled: false, Version: "", User: "alice"},
			},
		}

		payload := buildInventoryPayload("tenant-1", "host1", userResult)

		if payload.TenantID != "tenant-1" {
			t.Errorf("TenantID = %q, want %q", payload.TenantID, "tenant-1")
		}
		if payload.MachineName != "host1" {
			t.Errorf("MachineName = %q, want %q", payload.MachineName, "host1")
		}
		if payload.User != "alice" {
			t.Errorf("User = %q, want %q", payload.User, "alice")
		}
		if len(payload.Agents) != 2 {
			t.Fatalf("len(Agents) = %d, want 2", len(payload.Agents))
		}

		assertAgent(t, payload.Agents[0], "Cursor", strPtr("1.2.3"), true)
		assertAgent(t, payload.Agents[1], "Aider", nil, false)
	})

	t.Run("empty agents", func(t *testing.T) {
		t.Parallel()
		userResult := agentdetect.UserResult{
			User:   "bob",
			Agents: nil,
		}

		payload := buildInventoryPayload("", "host2", userResult)

		if payload.TenantID != "" {
			t.Errorf("TenantID = %q, want empty", payload.TenantID)
		}
		if payload.User != "bob" {
			t.Errorf("User = %q, want %q", payload.User, "bob")
		}
		if len(payload.Agents) != 0 {
			t.Errorf("len(Agents) = %d, want 0", len(payload.Agents))
		}
	})
}

func assertAgent(t *testing.T, agent api.AgentInventoryEntry, name string, version *string, mcp bool) {
	t.Helper()
	if agent.Name != name {
		t.Errorf("Name = %q, want %q", agent.Name, name)
	}
	if agent.ArmisMCPInstalled != mcp {
		t.Errorf("ArmisMCPInstalled = %v, want %v", agent.ArmisMCPInstalled, mcp)
	}
	if version == nil {
		if agent.Version != nil {
			t.Errorf("Version = %v, want nil", agent.Version)
		}
	} else {
		if agent.Version == nil || *agent.Version != *version {
			t.Errorf("Version = %v, want %q", agent.Version, *version)
		}
	}
}

func strPtr(s string) *string {
	return &s
}
