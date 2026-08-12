package history

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

const (
	envProd    = "https://moose.armis.com"
	envDev     = "https://moose-dev.armis.com"
	tenantA    = "tenant-a"
	tenantB    = "tenant-b"
	sampleScan = "scan-1"
)

func newEntry(scanID, tenantID, baseURL string, startedAt time.Time) Entry {
	return Entry{
		BaseURL:      baseURL,
		TenantID:     tenantID,
		ScanID:       scanID,
		ArtifactType: "repo",
		Artifact:     "example",
		StartedAt:    startedAt,
	}
}

func TestSaveAndLatest(t *testing.T) {
	store := NewStoreWithDir(t.TempDir())

	now := time.Now().UTC().Truncate(time.Second)
	if err := store.Save(newEntry(sampleScan, tenantA, envProd, now)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := store.Latest(envProd, tenantA)
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got == nil {
		t.Fatal("Latest returned nil for saved entry")
	}
	if got.ScanID != sampleScan || got.TenantID != tenantA {
		t.Errorf("Latest = %+v, want scan_id=%s tenant_id=%s", got, sampleScan, tenantA)
	}
	if got.SchemaVersion != schemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", got.SchemaVersion, schemaVersion)
	}
}

func TestSavePersistsFileWithOwnerOnlyPerms(t *testing.T) {
	dir := t.TempDir()
	store := NewStoreWithDir(dir)

	if err := store.Save(newEntry(sampleScan, tenantA, envProd, time.Now())); err != nil {
		t.Fatalf("Save: %v", err)
	}

	path := filepath.Join(dir, storeFileName)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("expected history file: %v", err)
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("history file perm = %o, want 600", perm)
		}
	}
}

func TestLatestPicksMostRecentForTenant(t *testing.T) {
	store := NewStoreWithDir(t.TempDir())

	older := time.Now().UTC().Add(-2 * time.Hour)
	newer := time.Now().UTC().Add(-1 * time.Hour)

	if err := store.Save(newEntry("scan-old", tenantA, envProd, older)); err != nil {
		t.Fatalf("Save old: %v", err)
	}
	if err := store.Save(newEntry("scan-new", tenantA, envProd, newer)); err != nil {
		t.Fatalf("Save new: %v", err)
	}
	// Also save an unrelated entry for tenant B to prove scoping is honored.
	if err := store.Save(newEntry("scan-b", tenantB, envProd, time.Now())); err != nil {
		t.Fatalf("Save b: %v", err)
	}

	got, err := store.Latest(envProd, tenantA)
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got == nil || got.ScanID != "scan-new" {
		t.Errorf("Latest for tenantA = %+v, want scan-new", got)
	}
}

func TestLatestScopedByBaseURL(t *testing.T) {
	store := NewStoreWithDir(t.TempDir())

	if err := store.Save(newEntry("prod-scan", tenantA, envProd, time.Now())); err != nil {
		t.Fatalf("Save prod: %v", err)
	}
	if err := store.Save(newEntry("dev-scan", tenantA, envDev, time.Now())); err != nil {
		t.Fatalf("Save dev: %v", err)
	}

	prod, err := store.Latest(envProd, tenantA)
	if err != nil || prod == nil || prod.ScanID != "prod-scan" {
		t.Errorf("Latest(prod) = %+v, err=%v; want prod-scan", prod, err)
	}
	dev, err := store.Latest(envDev, tenantA)
	if err != nil || dev == nil || dev.ScanID != "dev-scan" {
		t.Errorf("Latest(dev) = %+v, err=%v; want dev-scan", dev, err)
	}
}

func TestLatestReturnsNilWhenMissing(t *testing.T) {
	store := NewStoreWithDir(t.TempDir())

	got, err := store.Latest(envProd, tenantA)
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got != nil {
		t.Errorf("Latest = %+v, want nil", got)
	}
}

func TestSaveTrimsToMaxEntries(t *testing.T) {
	store := NewStoreWithDir(t.TempDir())

	base := time.Now().UTC()
	total := MaxEntries + 5
	for i := 0; i < total; i++ {
		entry := newEntry(
			// Every entry gets a unique scan_id so nothing dedups.
			"scan-"+padIndex(i),
			tenantA,
			envProd,
			base.Add(time.Duration(i)*time.Minute),
		)
		if err := store.Save(entry); err != nil {
			t.Fatalf("Save[%d]: %v", i, err)
		}
	}

	entries, err := store.read()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != MaxEntries {
		t.Fatalf("kept %d entries, want %d", len(entries), MaxEntries)
	}
	// Newest first — the oldest 5 should have been evicted.
	if entries[0].ScanID != "scan-"+padIndex(total-1) {
		t.Errorf("newest entry = %s, want scan-%s", entries[0].ScanID, padIndex(total-1))
	}
	oldestKept := "scan-" + padIndex(total-MaxEntries)
	if entries[len(entries)-1].ScanID != oldestKept {
		t.Errorf("oldest retained = %s, want %s", entries[len(entries)-1].ScanID, oldestKept)
	}
}

func TestSaveDedupsSameTriple(t *testing.T) {
	store := NewStoreWithDir(t.TempDir())

	older := time.Now().UTC().Add(-1 * time.Hour)
	newer := time.Now().UTC()

	first := newEntry(sampleScan, tenantA, envProd, older)
	first.Artifact = "old-artifact"
	if err := store.Save(first); err != nil {
		t.Fatalf("Save first: %v", err)
	}
	second := newEntry(sampleScan, tenantA, envProd, newer)
	second.Artifact = "new-artifact"
	if err := store.Save(second); err != nil {
		t.Fatalf("Save second: %v", err)
	}

	entries, err := store.read()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected dedup to 1 entry, got %d", len(entries))
	}
	if entries[0].Artifact != "new-artifact" {
		t.Errorf("expected latest write to win, got %q", entries[0].Artifact)
	}
}

func TestSaveRejectsMissingFields(t *testing.T) {
	store := NewStoreWithDir(t.TempDir())

	cases := []struct {
		name  string
		entry Entry
	}{
		{"missing scan_id", Entry{BaseURL: envProd, TenantID: tenantA}},
		{"missing tenant_id", Entry{BaseURL: envProd, ScanID: sampleScan}},
		{"missing base_url", Entry{TenantID: tenantA, ScanID: sampleScan}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := store.Save(tc.entry); err == nil {
				t.Error("expected error for missing field, got nil")
			}
		})
	}
}

func TestLatestIgnoresCorruptFile(t *testing.T) {
	dir := t.TempDir()
	store := NewStoreWithDir(dir)
	// Write garbage in place of a valid history file.
	if err := os.WriteFile(filepath.Join(dir, storeFileName), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}

	got, err := store.Latest(envProd, tenantA)
	if err != nil {
		t.Fatalf("Latest returned error for corrupt file: %v", err)
	}
	if got != nil {
		t.Errorf("Latest = %+v, want nil for corrupt file", got)
	}
}

func TestSaveNormalizesBaseURL(t *testing.T) {
	store := NewStoreWithDir(t.TempDir())

	if err := store.Save(newEntry(sampleScan, tenantA, "  HTTPS://Moose.Armis.com/  ", time.Now())); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := store.Latest("https://moose.armis.com", tenantA)
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got == nil {
		t.Fatal("Latest returned nil after normalization")
	}
}

func TestSaveEncodesJSONArray(t *testing.T) {
	dir := t.TempDir()
	store := NewStoreWithDir(dir)

	if err := store.Save(newEntry(sampleScan, tenantA, envProd, time.Now())); err != nil {
		t.Fatalf("Save: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, storeFileName)) //nolint:gosec // test file under t.TempDir
	if err != nil {
		t.Fatalf("read history: %v", err)
	}
	var out []Entry
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("history file must be a JSON array of entries: %v (%s)", err, raw)
	}
}

// TestSaveIsAtomic verifies the temp-file+rename write path: after a Save,
// the directory holds exactly the history file (no leftover *.tmp), the file
// is valid JSON, and it carries owner-only perms — i.e. a reader never sees a
// half-written file.
func TestSaveIsAtomic(t *testing.T) {
	dir := t.TempDir()
	store := NewStoreWithDir(dir)

	if err := store.Save(newEntry(sampleScan, tenantA, envProd, time.Now())); err != nil {
		t.Fatalf("Save: %v", err)
	}

	names, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, n := range names {
		if n.Name() != storeFileName {
			t.Errorf("unexpected leftover file in store dir: %q (temp file not cleaned up?)", n.Name())
		}
	}

	raw, err := os.ReadFile(filepath.Join(dir, storeFileName)) //nolint:gosec // test file under t.TempDir
	if err != nil {
		t.Fatalf("read history: %v", err)
	}
	var out []Entry
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("history file is not valid JSON after atomic write: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, statErr := os.Stat(filepath.Join(dir, storeFileName))
		if statErr != nil {
			t.Fatalf("stat: %v", statErr)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("history file perm = %o after atomic write, want 600", perm)
		}
	}
}

// TestConcurrentSavesKeepFileValid hammers Save from several goroutines. The
// store is last-writer-wins under concurrency (documented), but the atomic
// rename guarantees the file on disk is always complete, parseable JSON —
// never a torn write.
func TestConcurrentSavesKeepFileValid(t *testing.T) {
	dir := t.TempDir()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Each goroutine gets its own Store handle (as real callers do
			// via NewStore), all pointing at the same dir.
			_ = NewStoreWithDir(dir).Save(newEntry("scan-"+padIndex(i), tenantA, envProd, time.Now()))
		}(i)
	}
	wg.Wait()

	raw, err := os.ReadFile(filepath.Join(dir, storeFileName)) //nolint:gosec // test file under t.TempDir
	if err != nil {
		t.Fatalf("read history after concurrent writes: %v", err)
	}
	var out []Entry
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("history file corrupt after concurrent writes: %v\n%s", err, raw)
	}
	if len(out) == 0 {
		t.Error("expected at least one entry to survive concurrent writes")
	}
}

// padIndex zero-pads an integer to a fixed 4-digit width so lexicographic
// scan_id ordering matches numeric ordering in the assertion above.
func padIndex(i int) string {
	buf := []byte("0000")
	for k := len(buf) - 1; k >= 0 && i > 0; k-- {
		buf[k] = byte('0' + i%10)
		i /= 10
	}
	return string(buf)
}
