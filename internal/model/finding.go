// Package model defines the data structures for security scan findings and results.
package model

// Severity represents the severity level of a security finding.
type Severity string

const (
	// SeverityInfo represents informational findings.
	SeverityInfo Severity = "INFO"
	// SeverityLow represents low severity findings.
	SeverityLow Severity = "LOW"
	// SeverityMedium represents medium severity findings.
	SeverityMedium Severity = "MEDIUM"
	// SeverityHigh represents high severity findings.
	SeverityHigh Severity = "HIGH"
	// SeverityCritical represents critical severity findings.
	SeverityCritical Severity = "CRITICAL"
)

// FindingType represents the type of security finding.
type FindingType string

const (
	// FindingTypeVulnerability represents a vulnerability finding.
	FindingTypeVulnerability FindingType = "VULNERABILITY"
	// FindingTypeSCA represents a software composition analysis finding.
	FindingTypeSCA FindingType = "SCA"
	// FindingTypeSecret represents a secret detection finding.
	FindingTypeSecret FindingType = "SECRET"
	// FindingTypeLicense represents a license compliance finding.
	FindingTypeLicense FindingType = "LICENSE"
)

// Finding represents a single security finding from a scan.
type Finding struct {
	ID               string      `json:"id"`
	Type             FindingType `json:"type"`
	Severity         Severity    `json:"severity"`
	Title            string      `json:"title"`
	Description      string      `json:"description"`
	File             string      `json:"file,omitempty"`
	StartLine        int         `json:"start_line,omitempty"`
	EndLine          int         `json:"end_line,omitempty"`
	StartColumn      int         `json:"start_column,omitempty"`
	EndColumn        int         `json:"end_column,omitempty"`
	CodeSnippet      string      `json:"code_snippet,omitempty"`
	SnippetStartLine int         `json:"snippet_start_line,omitempty"`
	CVEs             []string    `json:"cves,omitempty"`
	CWEs             []string    `json:"cwes,omitempty"`
	FindingCategory  string      `json:"finding_category,omitempty"`
	Package          string      `json:"package,omitempty"`
	Version          string      `json:"version,omitempty"`
	FixVersion       string      `json:"fix_version,omitempty"`
}

// ScanResult represents the complete result of a security scan.
type ScanResult struct {
	ScanID    string    `json:"scan_id"`
	Status    string    `json:"status"`
	Findings  []Finding `json:"findings"`
	Summary   Summary   `json:"summary"`
	StartedAt string    `json:"started_at"`
	EndedAt   string    `json:"ended_at"`
}

// Summary provides aggregate statistics about scan findings.
type Summary struct {
	Total                  int                 `json:"total"`
	BySeverity             map[Severity]int    `json:"by_severity"`
	ByType                 map[FindingType]int `json:"by_type"`
	ByCategory             map[string]int      `json:"by_category"`
	FilteredNonExploitable int                 `json:"filtered_non_exploitable"`
}

// IngestUploadResponse represents the response from uploading a scan artifact.
type IngestUploadResponse struct {
	ScanID       string `json:"scan_id"`
	ArtifactType string `json:"artifact_type"`
	TenantID     string `json:"tenant_id"`
	Filename     string `json:"filename"`
	Message      string `json:"message"`
}

// IngestStatusData represents the status information for a scan ingestion.
type IngestStatusData struct {
	ArtifactType   string  `json:"artifact_type"`
	CompletedAt    *string `json:"completed_at"`
	ExpirationTime string  `json:"expiration_time"`
	FileBytes      int64   `json:"file_bytes"`
	FileName       string  `json:"file_name"`
	LastError      *string `json:"last_error"`
	ScanID         string  `json:"scan_id"`
	ScanStatus     string  `json:"scan_status"`
	ScanType       string  `json:"scan_type"`
	StartedAt      string  `json:"started_at"`
	TenantID       string  `json:"tenant_id"`
	UpdatedAt      string  `json:"updated_at"`
}

// IngestStatusResponse represents the response from checking scan status.
type IngestStatusResponse struct {
	Data []IngestStatusData `json:"data"`
}

// CodeLocation represents the location of a finding in source code.
type CodeLocation struct {
	Branch           string   `json:"branch"`
	FileName         *string  `json:"file_name"`
	StartCol         *int     `json:"start_col"`
	StartLine        *int     `json:"start_line"`
	EndCol           *int     `json:"end_col"`
	EndLine          *int     `json:"end_line"`
	Snippet          *string  `json:"snippet"`
	HasSecret        bool     `json:"has_secret"`
	CodeSnippetLines []string `json:"code_snippet_lines"`
	SnippetStartLine *int     `json:"snippet_start_line"`
	SnippetEndLine   *int     `json:"snippet_end_line"`
}

// ExtraData contains additional metadata for a finding.
type ExtraData struct {
	CodeLocation CodeLocation `json:"code_location"`
}

// Label represents a classification label for a finding.
type Label struct {
	Score       *float64 `json:"score"`
	Value       string   `json:"value"`
	Description string   `json:"description"`
	Color       *string  `json:"color"`
	LabelTypes  []string `json:"label_types"`
}

// NormalizedTask represents a normalized security task from the API.
type NormalizedTask struct {
	FindingID       string    `json:"finding_id"`
	AssetType       string    `json:"asset_type"`
	ClosedReason    *string   `json:"closed_reason"`
	ClosedTimestamp *string   `json:"closed_timestamp"`
	ExtraData       ExtraData `json:"extra_data"`
	RemediationType string    `json:"remediation_type"`
	ToolCreated     string    `json:"tool_created"`
	ToolLastSeen    string    `json:"tool_last_seen"`
	ToolSeverity    string    `json:"tool_severity"`
	ToolUpdated     string    `json:"tool_updated"`
	Whitelisted     bool      `json:"whitelisted"`
	Labels          []Label   `json:"labels"`
	LongDescription *string   `json:"long_description"`
}

// OWASPCategory represents an OWASP security category.
type OWASPCategory struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// VulnerabilityTypeMetadata contains metadata about a vulnerability type.
type VulnerabilityTypeMetadata struct {
	CVEs                    []string        `json:"cves"`
	CWEs                    []string        `json:"cwes"`
	LongDescriptionMarkdown string          `json:"long_description_markdown"`
	OWASPCategories         []OWASPCategory `json:"owasp_categories"`
	URLs                    []string        `json:"urls"`
}

// NormalizedRemediation represents remediation information from the API.
type NormalizedRemediation struct {
	RemediationID                 string                    `json:"remediation_id"`
	Description                   string                    `json:"description"`
	SecurityFindingClassification interface{}               `json:"security_finding_classification"`
	FindingCategory               interface{}               `json:"finding_category"`
	PublishedDate                 interface{}               `json:"published_date"`
	RemediationStatus             interface{}               `json:"remediation_status"`
	RemediationType               string                    `json:"remediation_type"`
	ToolCreated                   string                    `json:"tool_created"`
	ToolLastSeen                  string                    `json:"tool_last_seen"`
	ToolSeverity                  string                    `json:"tool_severity"`
	ToolUpdated                   string                    `json:"tool_updated"`
	VulnerabilityTypeMetadata     VulnerabilityTypeMetadata `json:"vulnerability_type_metadata"`
}

// NormalizedFinding represents a normalized finding from the API.
type NormalizedFinding struct {
	NormalizedRemediation NormalizedRemediation `json:"normalized_remediation"`
	NormalizedTask        NormalizedTask        `json:"normalized_task"`
}

// CodeAsset represents a code repository asset.
type CodeAsset struct {
	Description    string   `json:"description"`
	IsFork         bool     `json:"is_fork"`
	IsPrivate      bool     `json:"is_private"`
	Languages      []string `json:"languages"`
	LastScanned    string   `json:"last_scanned"`
	Owner          string   `json:"owner"`
	ProjectURL     string   `json:"project_url"`
	RepositoryName string   `json:"repository_name"`
}

// ScanResultData represents scan result data from the API.
type ScanResultData struct {
	ScanID    string              `json:"scan_id"`
	ScanTime  float64             `json:"scan_time"`
	CodeAsset CodeAsset           `json:"code_asset"`
	Findings  []NormalizedFinding `json:"findings"`
}

// NormalizedResultsData represents normalized results data from the API.
type NormalizedResultsData struct {
	TenantID    string           `json:"tenant_id"`
	ScanResults []ScanResultData `json:"scan_results"`
}

// Pagination contains pagination information for API responses.
type Pagination struct {
	NextCursor *string `json:"next_cursor"`
	Limit      int     `json:"limit"`
}

// NormalizedResultsResponse represents the API response for normalized results.
type NormalizedResultsResponse struct {
	Data       NormalizedResultsData `json:"data"`
	Pagination Pagination            `json:"pagination"`
}
