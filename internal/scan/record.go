package scan

import (
	"github.com/ArmisSecurity/armis-cli/internal/scan/history"
)

// RecordScanStarted persists the scan_id the API just handed us so a later
// `armis-cli scan status` (without an argument) can look it up. This is
// best-effort: a failure to write the history file must NEVER break a scan
// that has already been dispatched, so any error is swallowed here.
//
// The scan-history store is per-user, scoped by (base_url, tenant_id), and
// capped at history.MaxEntries entries so the on-disk footprint stays small.
//
// Fields:
//   - baseURL: the API base URL the client is talking to. Different Armis
//     environments (prod, dev, a local stack) get separate history buckets.
//   - tenantID / scanID: identify the scan on the server side.
//   - artifactType: one of "repo", "image", "sbom" — carried purely so the
//     `scan status` output can label the run.
//   - artifact: a short human label (repo path, image name, sbom filename).
//     Optional; empty is fine.
func RecordScanStarted(baseURL, tenantID, scanID, artifactType, artifact string) {
	_ = history.NewStore().Save(history.Entry{
		BaseURL:      baseURL,
		TenantID:     tenantID,
		ScanID:       scanID,
		ArtifactType: artifactType,
		Artifact:     artifact,
	})
}
