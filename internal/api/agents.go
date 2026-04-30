package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// AgentInventoryPayload is the request body for POST /api/v1/agents/inventory.
type AgentInventoryPayload struct {
	TenantID    string                `json:"tenant_id"`
	MachineName string                `json:"machine_name"`
	User        string                `json:"user"`
	Agents      []AgentInventoryEntry `json:"agents"`
}

// AgentInventoryEntry describes a single detected agent within an inventory report.
type AgentInventoryEntry struct {
	Name              string  `json:"name"`
	Version           *string `json:"version"`
	ArmisMCPInstalled bool    `json:"armis_mcp_installed"`
}

// ReportAgentInventory posts an agent inventory payload to the Armis Cloud API.
func (c *Client) ReportAgentInventory(ctx context.Context, payload AgentInventoryPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal agent inventory payload: %w", err)
	}

	endpoint := strings.TrimSuffix(c.baseURL, "/") + "/api/v1/agents/inventory"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	if err := c.setAuthHeader(ctx, req); err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to report agent inventory: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body read-only

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, MaxAPIResponseSize))
		return &APIError{StatusCode: resp.StatusCode, Body: string(bodyBytes)}
	}

	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}
