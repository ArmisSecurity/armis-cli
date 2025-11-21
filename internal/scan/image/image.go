package image

import (
        "context"
        "encoding/json"
        "fmt"
        "os"
        "os/exec"
        "path/filepath"
        "strings"
        "time"

        "github.com/silk-security/Moose-CLI/internal/api"
        "github.com/silk-security/Moose-CLI/internal/model"
        "github.com/silk-security/Moose-CLI/internal/progress"
)

const MaxImageSize = 5 * 1024 * 1024 * 1024

type Scanner struct {
        client       *api.Client
        noProgress   bool
        tenantID     string
        pageLimit    int
        includeTests bool
        timeout      time.Duration
}

func NewScanner(client *api.Client, noProgress bool, tenantID string, pageLimit int, includeTests bool, timeout time.Duration) *Scanner {
        return &Scanner{
                client:       client,
                noProgress:   noProgress,
                tenantID:     tenantID,
                pageLimit:    pageLimit,
                includeTests: includeTests,
                timeout:      timeout,
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
        tmpFileName := tmpFile.Name()

        fmt.Printf("Exporting image: %s\n", imageName)
        if err := s.exportImage(ctx, imageName, tmpFileName); err != nil {
                tmpFile.Close()
                os.Remove(tmpFileName)
                return nil, fmt.Errorf("failed to export image: %w", err)
        }

        result, scanErr := s.ScanTarball(ctx, tmpFileName)

        tmpFile.Close()
        os.Remove(tmpFileName)

        return result, scanErr
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

        uploadSpinner := progress.NewSpinner("Uploading image...", s.noProgress)
        uploadSpinner.Start()

        scanID, err := s.client.StartIngest(ctx, s.tenantID, "image", filepath.Base(tarballPath), file, info.Size())
        uploadSpinner.Stop()

        if err != nil {
                return nil, fmt.Errorf("failed to upload image: %w", err)
        }

        fmt.Printf("\nScan initiated with ID: %s\n", scanID)

        spinner := progress.NewSpinner("Waiting for scan to complete...", s.noProgress)
        spinner.Start()

        _, err = s.client.WaitForIngest(ctx, s.tenantID, scanID, 5*time.Second, s.timeout)
        elapsed := spinner.GetElapsed()
        spinner.Stop()

        if err != nil {
                return nil, fmt.Errorf("failed to wait for scan: %w", err)
        }

        fmt.Printf("Scan completed in %s. Fetching results...\n", formatElapsed(elapsed))

        findings, err := s.client.FetchAllNormalizedResults(ctx, s.tenantID, scanID, s.pageLimit)
        if err != nil {
                return nil, fmt.Errorf("failed to fetch results: %w", err)
        }

        result := buildScanResult(scanID, findings, s.client.IsDebug())
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

func buildScanResult(scanID string, normalizedFindings []model.NormalizedFinding, debug bool) *model.ScanResult {
        findings := convertNormalizedFindings(normalizedFindings, debug)

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

func convertNormalizedFindings(normalizedFindings []model.NormalizedFinding, debug bool) []model.Finding {
        var findings []model.Finding

        for i, nf := range normalizedFindings {
                if isEmptyFinding(nf) {
                        continue
                }

                if debug {
                        rawJSON, _ := json.Marshal(nf)
                        fmt.Printf("\n=== DEBUG: Finding #%d Raw JSON ===\n%s\n=== END DEBUG ===\n\n", i+1, string(rawJSON))
                }

                finding := model.Finding{
                        ID:          nf.NormalizedTask.FindingID,
                        Severity:    mapSeverity(nf.NormalizedRemediation.ToolSeverity),
                        Description: nf.NormalizedRemediation.Description,
                        CVEs:        nf.NormalizedRemediation.VulnerabilityTypeMetadata.CVEs,
                        CWEs:        nf.NormalizedRemediation.VulnerabilityTypeMetadata.CWEs,
                }

                if finding.Description == "" {
                        if nf.NormalizedRemediation.VulnerabilityTypeMetadata.LongDescriptionMarkdown != "" {
                                finding.Description = nf.NormalizedRemediation.VulnerabilityTypeMetadata.LongDescriptionMarkdown
                        } else if nf.NormalizedTask.LongDescription != nil {
                                finding.Description = *nf.NormalizedTask.LongDescription
                        }
                }

                finding.Description = cleanDescription(finding.Description)

                if nf.NormalizedRemediation.FindingCategory != nil {
                        if category, ok := nf.NormalizedRemediation.FindingCategory.(string); ok {
                                finding.FindingCategory = category
                        }
                }

                loc := nf.NormalizedTask.ExtraData.CodeLocation
                if loc.FileName != nil {
                        finding.File = *loc.FileName
                }
                if loc.StartLine != nil {
                        finding.StartLine = *loc.StartLine
                }
                if loc.EndLine != nil {
                        finding.EndLine = *loc.EndLine
                }
                if loc.StartCol != nil {
                        finding.StartColumn = *loc.StartCol
                }
                if loc.EndCol != nil {
                        finding.EndColumn = *loc.EndCol
                }

                if len(loc.CodeSnippetLines) > 0 {
                        finding.CodeSnippet = strings.Join(loc.CodeSnippetLines, "\n")
                } else if loc.Snippet != nil {
                        finding.CodeSnippet = *loc.Snippet
                }

                if loc.SnippetStartLine != nil {
                        finding.SnippetStartLine = *loc.SnippetStartLine
                }

                if len(nf.NormalizedRemediation.VulnerabilityTypeMetadata.CVEs) > 0 {
                        finding.Type = model.FindingTypeVulnerability
                }

                if loc.HasSecret {
                        finding.Type = model.FindingTypeSecret
                }

                if finding.Type == "" {
                        finding.Type = model.FindingTypeSCA
                }

                finding.Title = finding.Description

                findings = append(findings, finding)
        }

        return findings
}

func cleanDescription(desc string) string {
        lines := strings.Split(desc, "\n")
        var cleaned []string
        
        for _, line := range lines {
                line = strings.TrimSpace(line)
                if strings.HasPrefix(line, "Code_location -") ||
                   strings.HasPrefix(line, "Code Blob -") ||
                   strings.HasPrefix(line, "Confidence -") {
                        continue
                }
                if line != "" {
                        cleaned = append(cleaned, line)
                }
        }
        
        return strings.Join(cleaned, " ")
}

func isEmptyFinding(nf model.NormalizedFinding) bool {
        return nf.NormalizedRemediation.RemediationID == "" &&
                nf.NormalizedRemediation.Description == "" &&
                len(nf.NormalizedRemediation.VulnerabilityTypeMetadata.CVEs) == 0 &&
                len(nf.NormalizedRemediation.VulnerabilityTypeMetadata.CWEs) == 0
}

func mapSeverity(toolSeverity string) model.Severity {
        switch strings.ToUpper(toolSeverity) {
        case "CRITICAL":
                return model.SeverityCritical
        case "HIGH":
                return model.SeverityHigh
        case "MEDIUM":
                return model.SeverityMedium
        case "LOW":
                return model.SeverityLow
        default:
                return model.SeverityInfo
        }
}

func formatElapsed(d time.Duration) string {
        d = d.Round(time.Second)
        minutes := int(d.Minutes())
        seconds := int(d.Seconds()) % 60
        if minutes > 0 {
                return fmt.Sprintf("%dm %ds", minutes, seconds)
        }
        return fmt.Sprintf("%ds", seconds)
}
