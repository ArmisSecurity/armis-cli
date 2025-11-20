package repo

import (
        "archive/tar"
        "compress/gzip"
        "context"
        "fmt"
        "io"
        "os"
        "path/filepath"
        "strings"

        "github.com/silk-security/Moose-CLI/internal/api"
        "github.com/silk-security/Moose-CLI/internal/model"
        "github.com/silk-security/Moose-CLI/internal/progress"
)

const MaxRepoSize = 2 * 1024 * 1024 * 1024

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

func (s *Scanner) Scan(ctx context.Context, path string) (*model.ScanResult, error) {
        absPath, err := filepath.Abs(path)
        if err != nil {
                return nil, fmt.Errorf("failed to resolve path: %w", err)
        }

        info, err := os.Stat(absPath)
        if err != nil {
                return nil, fmt.Errorf("failed to stat path: %w", err)
        }

        if !info.IsDir() {
                return nil, fmt.Errorf("path is not a directory: %s", absPath)
        }

        size, err := calculateDirSize(absPath)
        if err != nil {
                return nil, fmt.Errorf("failed to calculate directory size: %w", err)
        }

        if size > MaxRepoSize {
                return nil, fmt.Errorf("directory size (%d bytes) exceeds maximum allowed size (%d bytes)", size, MaxRepoSize)
        }

        pr, pw := io.Pipe()

        errChan := make(chan error, 1)
        go func() {
                defer pw.Close()
                errChan <- s.tarGzDirectory(absPath, pw)
        }()

        progressReader := progress.NewReader(pr, size, "Uploading repository", s.noProgress)

        scanID, err := s.client.StartIngest(ctx, s.tenantID, "repo", filepath.Base(absPath)+".tar.gz", progressReader, size)
        if err != nil {
                return nil, fmt.Errorf("failed to upload repository: %w", err)
        }

        if tarErr := <-errChan; tarErr != nil {
                return nil, fmt.Errorf("failed to tar directory: %w", tarErr)
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

func (s *Scanner) tarGzDirectory(sourcePath string, writer io.Writer) error {
        gzWriter := gzip.NewWriter(writer)
        defer gzWriter.Close()

        tarWriter := tar.NewWriter(gzWriter)
        defer tarWriter.Close()

        return filepath.Walk(sourcePath, func(path string, info os.FileInfo, err error) error {
                if err != nil {
                        return err
                }

                if shouldSkip(path, info) {
                        if info.IsDir() {
                                return filepath.SkipDir
                        }
                        return nil
                }

                header, err := tar.FileInfoHeader(info, "")
                if err != nil {
                        return err
                }

                relPath, err := filepath.Rel(sourcePath, path)
                if err != nil {
                        return err
                }
                header.Name = relPath

                if err := tarWriter.WriteHeader(header); err != nil {
                        return err
                }

                if !info.IsDir() {
                        file, err := os.Open(path)
                        if err != nil {
                                return err
                        }
                        defer file.Close()

                        _, err = io.Copy(tarWriter, file)
                        if err != nil {
                                return err
                        }
                }

                return nil
        })
}

func calculateDirSize(path string) (int64, error) {
        var size int64
        err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
                if err != nil {
                        return err
                }
                if shouldSkip(filePath, info) {
                        if info.IsDir() {
                                return filepath.SkipDir
                        }
                        return nil
                }
                if !info.IsDir() {
                        size += info.Size()
                }
                return nil
        })
        return size, err
}

func shouldSkip(path string, info os.FileInfo) bool {
        name := info.Name()

        skipDirs := []string{
                ".git", ".svn", ".hg",
                "node_modules", "vendor", "venv", ".venv",
                "__pycache__", ".pytest_cache",
                "target", "build", "dist", ".next",
                ".idea", ".vscode",
        }

        for _, dir := range skipDirs {
                if info.IsDir() && name == dir {
                        return true
                }
                if strings.Contains(path, string(filepath.Separator)+dir+string(filepath.Separator)) {
                        return true
                }
        }

        return false
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
