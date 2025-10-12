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
