package model

import "time"

type Severity string

const (
        SeverityInfo     Severity = "INFO"
        SeverityLow      Severity = "LOW"
        SeverityMedium   Severity = "MEDIUM"
        SeverityHigh     Severity = "HIGH"
        SeverityCritical Severity = "CRITICAL"
)

type FindingType string

const (
        FindingTypeVulnerability FindingType = "VULNERABILITY"
        FindingTypeSCA           FindingType = "SCA"
        FindingTypeSecret        FindingType = "SECRET"
        FindingTypeLicense       FindingType = "LICENSE"
)

type Finding struct {
        ID          string      `json:"id"`
        Type        FindingType `json:"type"`
        Severity    Severity    `json:"severity"`
        Title       string      `json:"title"`
        Description string      `json:"description"`
        File        string      `json:"file,omitempty"`
        Line        int         `json:"line,omitempty"`
        Column      int         `json:"column,omitempty"`
        CVE         string      `json:"cve,omitempty"`
        CWE         string      `json:"cwe,omitempty"`
        Package     string      `json:"package,omitempty"`
        Version     string      `json:"version,omitempty"`
        FixVersion  string      `json:"fix_version,omitempty"`
}

type ScanResult struct {
        ScanID    string    `json:"scan_id"`
        Status    string    `json:"status"`
        Findings  []Finding `json:"findings"`
        Summary   Summary   `json:"summary"`
        StartedAt time.Time `json:"started_at"`
        EndedAt   time.Time `json:"ended_at"`
}

type Summary struct {
        Total      int                 `json:"total"`
        BySeverity map[Severity]int    `json:"by_severity"`
        ByType     map[FindingType]int `json:"by_type"`
}

type IngestUploadResponse struct {
        ScanID       string `json:"scan_id"`
        ArtifactType string `json:"artifact_type"`
        TenantID     string `json:"tenant_id"`
        Filename     string `json:"filename"`
        Message      string `json:"message"`
}

type IngestStatusData struct {
        ArtifactType   string     `json:"artifact_type"`
        CompletedAt    *time.Time `json:"completed_at"`
        ExpirationTime string     `json:"expiration_time"`
        FileBytes      int64      `json:"file_bytes"`
        FileName       string     `json:"file_name"`
        LastError      *string    `json:"last_error"`
        ScanID         string     `json:"scan_id"`
        ScanStatus     string     `json:"scan_status"`
        ScanType       string     `json:"scan_type"`
        StartedAt      string     `json:"started_at"`
        TenantID       string     `json:"tenant_id"`
        UpdatedAt      string     `json:"updated_at"`
}

type IngestStatusResponse struct {
        Data []IngestStatusData `json:"data"`
}

type NormalizedResultsResponse struct {
        Data       []Finding `json:"data"`
        NextCursor *string   `json:"next_cursor"`
}
