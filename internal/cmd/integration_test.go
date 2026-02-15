package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/api"
	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/scan/repo"
	"github.com/ArmisSecurity/armis-cli/internal/scan/testhelpers"
	"github.com/ArmisSecurity/armis-cli/internal/testutil"
)

// createTestRepo creates a minimal repository for testing.
func createTestRepo(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main\n\nfunc main() {}"), 0600); err != nil {
		t.Fatalf("failed to create main.go: %v", err)
	}
	return tmpDir
}

func TestIntegration_RepoScan_HumanOutput(t *testing.T) {
	// Create test findings
	findings := []model.NormalizedFinding{
		testhelpers.CreateNormalizedFinding("finding-1", "CRITICAL", "sql_injection", []string{"CVE-2024-1234"}, []string{"CWE-89"}),
		testhelpers.CreateNormalizedFinding("finding-2", "HIGH", "sca", []string{"CVE-2024-5678"}, nil),
	}

	// Setup mock server
	serverURL := testutil.GetMockServerURL(t, findings)

	// Create scanner with mock server
	authProvider := testutil.NewTestAuthProvider("test-token")
	client, err := api.NewClient(serverURL, authProvider, false, 0, api.WithAllowLocalURLs(true))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	scanner := repo.NewScanner(client, true, "test-tenant", 500, false, 60*time.Second, false).
		WithPollInterval(10 * time.Millisecond)

	// Create test repo
	repoPath := createTestRepo(t)

	// Execute scan
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := scanner.Scan(ctx, repoPath)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Verify result
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if len(result.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(result.Findings))
	}

	// Format as human output
	formatter, err := output.GetFormatter("human")
	if err != nil {
		t.Fatalf("failed to get formatter: %v", err)
	}

	var buf bytes.Buffer
	if err := formatter.Format(result, &buf); err != nil {
		t.Fatalf("failed to format output: %v", err)
	}

	outputStr := buf.String()

	// Verify human output contains expected elements
	if !strings.Contains(outputStr, "CRITICAL") && !strings.Contains(strings.ToLower(outputStr), "critical") {
		t.Error("human output should contain CRITICAL severity")
	}
	if !strings.Contains(outputStr, "HIGH") && !strings.Contains(strings.ToLower(outputStr), "high") {
		t.Error("human output should contain HIGH severity")
	}
}

func TestIntegration_RepoScan_JSONOutput(t *testing.T) {
	findings := []model.NormalizedFinding{
		testhelpers.CreateNormalizedFinding("finding-json-1", "HIGH", "xss", []string{"CVE-2024-9999"}, []string{"CWE-79"}),
	}

	serverURL := testutil.GetMockServerURL(t, findings)

	authProvider := testutil.NewTestAuthProvider("test-token")
	client, err := api.NewClient(serverURL, authProvider, false, 0, api.WithAllowLocalURLs(true))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	scanner := repo.NewScanner(client, true, "test-tenant", 500, false, 60*time.Second, false).
		WithPollInterval(10 * time.Millisecond)

	repoPath := createTestRepo(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := scanner.Scan(ctx, repoPath)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	formatter, err := output.GetFormatter("json")
	if err != nil {
		t.Fatalf("failed to get formatter: %v", err)
	}

	var buf bytes.Buffer
	if err := formatter.Format(result, &buf); err != nil {
		t.Fatalf("failed to format output: %v", err)
	}

	// Verify valid JSON
	var jsonResult map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &jsonResult); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Verify expected fields
	if _, ok := jsonResult["findings"]; !ok {
		t.Error("JSON output should contain 'findings' field")
	}
	if _, ok := jsonResult["summary"]; !ok {
		t.Error("JSON output should contain 'summary' field")
	}
}

func TestIntegration_RepoScan_SARIFOutput(t *testing.T) {
	findings := []model.NormalizedFinding{
		testhelpers.CreateNormalizedFinding("finding-sarif-1", "MEDIUM", "misconfig", nil, []string{"CWE-200"}),
	}

	serverURL := testutil.GetMockServerURL(t, findings)

	authProvider := testutil.NewTestAuthProvider("test-token")
	client, err := api.NewClient(serverURL, authProvider, false, 0, api.WithAllowLocalURLs(true))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	scanner := repo.NewScanner(client, true, "test-tenant", 500, false, 60*time.Second, false).
		WithPollInterval(10 * time.Millisecond)

	repoPath := createTestRepo(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := scanner.Scan(ctx, repoPath)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	formatter, err := output.GetFormatter("sarif")
	if err != nil {
		t.Fatalf("failed to get formatter: %v", err)
	}

	var buf bytes.Buffer
	if err := formatter.Format(result, &buf); err != nil {
		t.Fatalf("failed to format output: %v", err)
	}

	// Verify valid SARIF JSON
	var sarifResult map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &sarifResult); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Verify SARIF schema
	if schema, ok := sarifResult["$schema"].(string); !ok || !strings.Contains(schema, "sarif") {
		t.Error("SARIF output should contain $schema field")
	}
	if _, ok := sarifResult["runs"]; !ok {
		t.Error("SARIF output should contain 'runs' field")
	}
}

func TestIntegration_RepoScan_JUnitOutput(t *testing.T) {
	findings := []model.NormalizedFinding{
		testhelpers.CreateNormalizedFinding("finding-junit-1", "LOW", "license_risk", nil, nil),
	}

	serverURL := testutil.GetMockServerURL(t, findings)

	authProvider := testutil.NewTestAuthProvider("test-token")
	client, err := api.NewClient(serverURL, authProvider, false, 0, api.WithAllowLocalURLs(true))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	scanner := repo.NewScanner(client, true, "test-tenant", 500, false, 60*time.Second, false).
		WithPollInterval(10 * time.Millisecond)

	repoPath := createTestRepo(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := scanner.Scan(ctx, repoPath)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	formatter, err := output.GetFormatter("junit")
	if err != nil {
		t.Fatalf("failed to get formatter: %v", err)
	}

	var buf bytes.Buffer
	if err := formatter.Format(result, &buf); err != nil {
		t.Fatalf("failed to format output: %v", err)
	}

	// Verify valid XML
	type TestSuites struct {
		XMLName xml.Name `xml:"testsuites"`
	}
	var suites TestSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("output is not valid XML: %v", err)
	}
}

func TestIntegration_RepoScan_FailOnCritical(t *testing.T) {
	findings := []model.NormalizedFinding{
		testhelpers.CreateNormalizedFinding("critical-finding", "CRITICAL", "secret", nil, nil),
		testhelpers.CreateNormalizedFinding("low-finding", "LOW", "info", nil, nil),
	}

	serverURL := testutil.GetMockServerURL(t, findings)

	authProvider := testutil.NewTestAuthProvider("test-token")
	client, err := api.NewClient(serverURL, authProvider, false, 0, api.WithAllowLocalURLs(true))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	scanner := repo.NewScanner(client, true, "test-tenant", 500, false, 60*time.Second, false).
		WithPollInterval(10 * time.Millisecond)

	repoPath := createTestRepo(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := scanner.Scan(ctx, repoPath)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Test ShouldFail with CRITICAL
	if !output.ShouldFail(result, []string{"CRITICAL"}) {
		t.Error("expected ShouldFail to return true when CRITICAL finding exists")
	}
}

func TestIntegration_RepoScan_FailOnNoMatch(t *testing.T) {
	findings := []model.NormalizedFinding{
		testhelpers.CreateNormalizedFinding("low-finding-1", "LOW", "info", nil, nil),
		testhelpers.CreateNormalizedFinding("medium-finding", "MEDIUM", "sca", nil, nil),
	}

	serverURL := testutil.GetMockServerURL(t, findings)

	authProvider := testutil.NewTestAuthProvider("test-token")
	client, err := api.NewClient(serverURL, authProvider, false, 0, api.WithAllowLocalURLs(true))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	scanner := repo.NewScanner(client, true, "test-tenant", 500, false, 60*time.Second, false).
		WithPollInterval(10 * time.Millisecond)

	repoPath := createTestRepo(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := scanner.Scan(ctx, repoPath)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Test ShouldFail with CRITICAL (no match)
	if output.ShouldFail(result, []string{"CRITICAL"}) {
		t.Error("expected ShouldFail to return false when no CRITICAL findings exist")
	}
}

func TestIntegration_RepoScan_EmptyResults(t *testing.T) {
	// Empty findings
	findings := []model.NormalizedFinding{}

	serverURL := testutil.GetMockServerURL(t, findings)

	authProvider := testutil.NewTestAuthProvider("test-token")
	client, err := api.NewClient(serverURL, authProvider, false, 0, api.WithAllowLocalURLs(true))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	scanner := repo.NewScanner(client, true, "test-tenant", 500, false, 60*time.Second, false).
		WithPollInterval(10 * time.Millisecond)

	repoPath := createTestRepo(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := scanner.Scan(ctx, repoPath)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}

	// Verify all formatters handle empty results
	formats := []string{"human", "json", "sarif", "junit"}
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			formatter, err := output.GetFormatter(format)
			if err != nil {
				t.Fatalf("failed to get %s formatter: %v", format, err)
			}

			var buf bytes.Buffer
			if err := formatter.Format(result, &buf); err != nil {
				t.Errorf("%s formatter failed on empty results: %v", format, err)
			}
		})
	}
}

func TestIntegration_RepoScan_ScanFailed(t *testing.T) {
	// Setup mock server that returns FAILED status
	serverURL := testutil.GetMockServerURLWithConfig(t, testutil.MockAPIConfig{
		FinalStatus: "FAILED",
		LastError:   "internal scanner error: dependency resolution failed",
	})

	authProvider := testutil.NewTestAuthProvider("test-token")
	client, err := api.NewClient(serverURL, authProvider, false, 0, api.WithAllowLocalURLs(true))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	scanner := repo.NewScanner(client, true, "test-tenant", 500, false, 60*time.Second, false).
		WithPollInterval(10 * time.Millisecond)

	repoPath := createTestRepo(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err = scanner.Scan(ctx, repoPath)
	if err == nil {
		t.Fatal("expected error for FAILED scan status")
	}

	// Verify error contains the last_error message
	if !strings.Contains(err.Error(), "failed") && !strings.Contains(err.Error(), "FAILED") {
		t.Errorf("error should indicate scan failure, got: %v", err)
	}
}
