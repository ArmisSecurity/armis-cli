package image

import (
        "context"
        "fmt"
        "os"
        "os/exec"
        "path/filepath"

        "github.com/silk-security/Moose-CLI/internal/api"
        "github.com/silk-security/Moose-CLI/internal/model"
        "github.com/silk-security/Moose-CLI/internal/progress"
)

const MaxImageSize = 5 * 1024 * 1024 * 1024

type Scanner struct {
        client     *api.Client
        noProgress bool
        tenantID   string
        pageLimit  int
}

func NewScanner(client *api.Client, noProgress bool, tenantID string, pageLimit int) *Scanner {
        return &Scanner{
                client:     client,
                noProgress: noProgress,
                tenantID:   tenantID,
                pageLimit:  pageLimit,
        }
}

func (s *Scanner) ScanImage(ctx context.Context, imageName string) (*model.ScanResult, error) {
        normalised, err := validateImageName(imageName)
        if err != nil {
                return nil, err
        }
        imageName = normalised

        if !isDockerAvailable() {
                return nil, fmt.Errorf("docker is not available. Please install Docker or Podman")
        }

        tmpFile, err := os.CreateTemp("", "armis-image-*.tar")
        if err != nil {
                return nil, fmt.Errorf("failed to create temp file: %w", err)
        }
        defer os.Remove(tmpFile.Name())
        defer tmpFile.Close()

        fmt.Printf("Exporting image: %s\n", imageName)
        if err := s.exportImage(ctx, imageName, tmpFile.Name()); err != nil {
                return nil, fmt.Errorf("failed to export image: %w", err)
        }

        return s.ScanTarball(ctx, tmpFile.Name())
}

func (s *Scanner) ScanTarball(ctx context.Context, tarballPath string) (*model.ScanResult, error) {
        info, err := os.Stat(tarballPath)
        if err != nil {
                return nil, fmt.Errorf("failed to stat tarball: %w", err)
        }

        if info.Size() > MaxImageSize {
                return nil, fmt.Errorf("tarball size (%d bytes) exceeds maximum allowed size (%d bytes)", info.Size(), MaxImageSize)
        }

        file, err := os.Open(tarballPath)
        if err != nil {
                return nil, fmt.Errorf("failed to open tarball: %w", err)
        }
        defer file.Close()

        progressReader := progress.NewReader(file, info.Size(), "Uploading image", s.noProgress)

        scanID, err := s.client.StartIngest(ctx, s.tenantID, "image", filepath.Base(tarballPath), progressReader, info.Size())
        if err != nil {
                return nil, fmt.Errorf("failed to upload image: %w", err)
        }

        fmt.Printf("\nScan initiated with ID: %s\n", scanID)

        spinner := progress.NewSpinner("Waiting for scan to complete...", s.noProgress)
        spinner.Start()

        _, err = s.client.WaitForIngest(ctx, s.tenantID, scanID, 5)
        spinner.Stop()

        if err != nil {
                return nil, fmt.Errorf("failed to wait for scan: %w", err)
        }

        fmt.Println("Scan completed. Fetching results...")

        findings, err := s.client.FetchAllNormalizedResults(ctx, s.tenantID, scanID, s.pageLimit)
        if err != nil {
                return nil, fmt.Errorf("failed to fetch results: %w", err)
        }

        result := buildScanResult(scanID, findings)
        return result, nil
}

func (s *Scanner) exportImage(ctx context.Context, imageName, outputPath string) error {
        dockerCmd := getDockerCommand()

        cmd := exec.CommandContext(ctx, dockerCmd, "pull", imageName)
        cmd.Stdout = os.Stdout
        cmd.Stderr = os.Stderr
        if err := cmd.Run(); err != nil {
                return fmt.Errorf("failed to pull image: %w", err)
        }

        cmd = exec.CommandContext(ctx, dockerCmd, "save", "-o", outputPath, imageName)
        cmd.Stdout = os.Stdout
        cmd.Stderr = os.Stderr
        if err := cmd.Run(); err != nil {
                return fmt.Errorf("failed to save image: %w", err)
        }

        return nil
}

func isDockerAvailable() bool {
        cmd := exec.Command("docker", "version")
        if err := cmd.Run(); err == nil {
                return true
        }

        cmd = exec.Command("podman", "version")
        if err := cmd.Run(); err == nil {
                return true
        }

        return false
}

func getDockerCommand() string {
        cmd := exec.Command("docker", "version")
        if err := cmd.Run(); err == nil {
                return "docker"
        }

        return "podman"
}

func buildScanResult(scanID string, findings []model.Finding) *model.ScanResult {
        summary := model.Summary{
                Total:      len(findings),
                BySeverity: make(map[model.Severity]int),
                ByType:     make(map[model.FindingType]int),
        }

        for _, finding := range findings {
                summary.BySeverity[finding.Severity]++
                summary.ByType[finding.Type]++
        }

        return &model.ScanResult{
                ScanID:   scanID,
                Status:   "completed",
                Findings: findings,
                Summary:  summary,
        }
}
