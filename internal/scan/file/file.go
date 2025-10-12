package file

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/silk-security/Moose-CLI/internal/api"
	"github.com/silk-security/Moose-CLI/internal/model"
	"github.com/silk-security/Moose-CLI/internal/progress"
)

const MaxFileSize = 50 * 1024 * 1024

type Scanner struct {
	client     *api.Client
	noProgress bool
}

func NewScanner(client *api.Client, noProgress bool) *Scanner {
	return &Scanner{
		client:     client,
		noProgress: noProgress,
	}
}

func (s *Scanner) Scan(ctx context.Context, filePath string) (*model.ScanResult, error) {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path: %w", err)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	if info.IsDir() {
		return nil, fmt.Errorf("path is a directory, not a file: %s", absPath)
	}

	if info.Size() > MaxFileSize {
		return nil, fmt.Errorf("file size (%d bytes) exceeds maximum allowed size (%d bytes)", info.Size(), MaxFileSize)
	}

	file, err := os.Open(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	progressReader := progress.NewReader(file, info.Size(), "Uploading file", s.noProgress)

	scanID, err := s.client.UploadFile(ctx, filepath.Base(absPath), progressReader, info.Size())
	if err != nil {
		return nil, fmt.Errorf("failed to upload file: %w", err)
	}

	fmt.Printf("\nScan initiated with ID: %s\n", scanID)
	fmt.Println("Waiting for scan results...")

	result, err := s.client.WaitForScan(ctx, scanID, 5)
	if err != nil {
		return nil, fmt.Errorf("failed to get scan results: %w", err)
	}

	return result, nil
}
