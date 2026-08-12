// Package history persists metadata for scans initiated by the CLI so that
// follow-up commands (e.g. `armis-cli scan status`) can look up the most
// recent scan without requiring the user to remember the scan_id.
//
// The file is a plain JSON array of entries scoped by (base_url, tenant_id).
// It lives alongside the SSO session file under ~/.armis so it inherits the
// same 0700 directory permissions and is stored owner-only (0600) on
// macOS/Linux. Corrupted or oversized files are treated as empty so a stale
// history file never breaks a scan.
package history

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	// storeDirName is the per-user Armis config directory (~/.armis). It
	// deliberately matches the SSO session file's directory so both share
	// the same 0700 protection.
	storeDirName = ".armis"
	// storeFileName is the history file within that directory.
	storeFileName = "scan-history.json"
	// schemaVersion versions the on-disk JSON so older readers can detect
	// (rather than mis-parse) a format bump.
	schemaVersion = 1
	// maxFileSize bounds reads to guard against a corrupted or maliciously
	// large history file exhausting memory.
	maxFileSize = 1 << 20 // 1MB
	// MaxEntries caps the number of retained scans. Older entries are
	// evicted on Save so the file can never grow without bound.
	MaxEntries = 20
)

// Entry describes one scan the CLI initiated.
type Entry struct {
	SchemaVersion int       `json:"schema_version"`
	BaseURL       string    `json:"base_url"`
	TenantID      string    `json:"tenant_id"`
	ScanID        string    `json:"scan_id"`
	ArtifactType  string    `json:"artifact_type"`
	Artifact      string    `json:"artifact,omitempty"`
	StartedAt     time.Time `json:"started_at"`
}

// Store persists Entry values to a per-user JSON file.
type Store struct {
	// dir overrides the directory containing the history file. Empty means
	// ~/.armis. Set by tests via NewStoreWithDir.
	dir string
}

// envDirOverride names the environment variable that lets tests redirect
// the history file away from the real ~/.armis directory. It is
// deliberately undocumented for end users — only the CLI's own test suite
// needs to override the default path.
const envDirOverride = "ARMIS_HISTORY_DIR"

// NewStore returns a Store backed by ~/.armis/scan-history.json (or the
// directory in $ARMIS_HISTORY_DIR when that env var is set, for tests).
//
// armis:ignore cwe:22 reason:ARMIS_HISTORY_DIR is a process-local env var (same trust boundary as ARMIS_API_URL/ARMIS_API_TOKEN); the directory is combined with a hardcoded filename and only ever stores our own JSON blob
func NewStore() *Store {
	return &Store{dir: os.Getenv(envDirOverride)}
}

// NewStoreWithDir returns a Store rooted at dir (test-only helper).
func NewStoreWithDir(dir string) *Store {
	return &Store{dir: dir}
}

// Save inserts entry, replacing any existing entry with the same
// (base_url, tenant_id, scan_id) triple, then trims the file to the most
// recent MaxEntries scans. StartedAt is stamped to time.Now() when zero.
func (s *Store) Save(entry Entry) error {
	if entry.ScanID == "" {
		return errors.New("scan_id is required")
	}
	if entry.TenantID == "" {
		return errors.New("tenant_id is required")
	}
	if entry.BaseURL == "" {
		return errors.New("base_url is required")
	}
	entry.SchemaVersion = schemaVersion
	entry.BaseURL = normalizeBaseURL(entry.BaseURL)
	if entry.StartedAt.IsZero() {
		entry.StartedAt = time.Now().UTC()
	} else {
		entry.StartedAt = entry.StartedAt.UTC()
	}

	entries, _ := s.read()

	kept := entries[:0]
	for _, e := range entries {
		if e.ScanID == entry.ScanID &&
			e.TenantID == entry.TenantID &&
			normalizeBaseURL(e.BaseURL) == entry.BaseURL {
			continue
		}
		kept = append(kept, e)
	}
	kept = append(kept, entry)

	sort.SliceStable(kept, func(i, j int) bool {
		return kept[i].StartedAt.After(kept[j].StartedAt)
	})
	if len(kept) > MaxEntries {
		kept = kept[:MaxEntries]
	}

	return s.write(kept)
}

// Latest returns the most recent entry matching (baseURL, tenantID), or
// (nil, nil) when no such entry exists. A corrupted history file is treated
// as absent so the caller can prompt for an explicit scan_id.
func (s *Store) Latest(baseURL, tenantID string) (*Entry, error) {
	if tenantID == "" || baseURL == "" {
		return nil, nil
	}
	entries, err := s.read()
	if err != nil {
		return nil, nil //nolint:nilerr // unreadable/corrupted file treated as absent
	}
	baseURL = normalizeBaseURL(baseURL)
	var best *Entry
	for i := range entries {
		e := entries[i]
		if e.TenantID != tenantID {
			continue
		}
		if normalizeBaseURL(e.BaseURL) != baseURL {
			continue
		}
		if best == nil || e.StartedAt.After(best.StartedAt) {
			eCopy := e
			best = &eCopy
		}
	}
	return best, nil
}

// Path returns the resolved history file path (for diagnostic messages).
func (s *Store) Path() string {
	path, _ := s.filePath()
	return path
}

// read loads and parses the history file. A missing file yields an empty
// slice; an oversized/invalid file yields an error so Save can decide to
// overwrite it rather than appending to garbage.
func (s *Store) read() ([]Entry, error) {
	path, err := s.filePath()
	if err != nil {
		return nil, err
	}
	// armis:ignore cwe:367 reason:stat-then-read race is benign; worst case reads a stale entry, no security impact
	info, statErr := os.Stat(path)
	if statErr != nil {
		if os.IsNotExist(statErr) {
			return nil, nil
		}
		return nil, statErr
	}
	if info.Size() > maxFileSize {
		return nil, fmt.Errorf("history file %s exceeds %d bytes", path, maxFileSize)
	}
	// armis:ignore cwe:22 reason:path derived from os.UserHomeDir + hardcoded segments
	data, err := os.ReadFile(path) //nolint:gosec // path derived from os.UserHomeDir + hardcoded segments
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	var entries []Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("history file is not valid JSON: %w", err)
	}
	return entries, nil
}

// write persists entries to the 0600 file, creating ~/.armis (0700) if
// needed. An empty slice deletes the file so the on-disk footprint is
// nothing when the user has no scan history.
//
// The write is atomic: entries are marshaled to a temp file in the same
// directory and then renamed over the target. os.Rename is atomic within a
// filesystem, so a crash mid-write (or a concurrent scan writing at the same
// time) can never leave a half-written / corrupt history file — a reader
// always sees either the old file or the fully-written new one. Under true
// concurrency the semantics are last-writer-wins, which is acceptable for a
// best-effort convenience cache (a lost entry just means one scan won't show
// up in the no-arg `scan status` fallback).
func (s *Store) write(entries []Entry) error {
	path, err := s.filePath()
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		if rerr := os.Remove(path); rerr != nil && !os.IsNotExist(rerr) {
			return rerr
		}
		return nil
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal history: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create history directory: %w", err)
	}
	// Write to a temp file in the same directory (so the rename stays within
	// one filesystem) then atomically swap it into place.
	// armis:ignore cwe:22 reason:dir derived from os.UserHomeDir + hardcoded segments
	tmp, err := os.CreateTemp(dir, ".scan-history-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp history file: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if we bail before the rename succeeds.
	defer func() { _ = os.Remove(tmpName) }()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to set history file mode: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to write history file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to flush history file: %w", err)
	}
	// armis:ignore cwe:22 reason:paths derived from os.UserHomeDir + hardcoded segments
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("failed to finalize history file: %w", err)
	}
	return nil
}

// filePath resolves the history file path: <dir>/scan-history.json where
// dir is the test override or ~/.armis.
func (s *Store) filePath() (string, error) {
	dir := s.dir
	if dir == "" {
		// armis:ignore cwe:22 reason:os.UserHomeDir is a trusted OS source; joined with hardcoded path segments
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot determine home directory: %w", err)
		}
		dir = filepath.Join(home, storeDirName)
	}
	return filepath.Join(dir, storeFileName), nil
}

// normalizeBaseURL canonicalizes a base URL so trivial spelling differences
// (trailing slash, case, whitespace) resolve to the same history bucket.
func normalizeBaseURL(u string) string {
	return strings.TrimRight(strings.ToLower(strings.TrimSpace(u)), "/")
}
