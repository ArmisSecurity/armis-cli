package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

type ScanResponse struct {
	ScanID string `json:"scan_id"`
}

type Finding struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	File        string `json:"file,omitempty"`
	Line        int    `json:"line,omitempty"`
	Column      int    `json:"column,omitempty"`
	CVE         string `json:"cve,omitempty"`
	CWE         string `json:"cwe,omitempty"`
	Package     string `json:"package,omitempty"`
	Version     string `json:"version,omitempty"`
	FixVersion  string `json:"fix_version,omitempty"`
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
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	ByType     map[string]int `json:"by_type"`
}

var scans = make(map[string]*ScanResult)

func main() {
	http.HandleFunc("/scans/repo", handleUpload)
	http.HandleFunc("/scans/image", handleUpload)
	http.HandleFunc("/scans/file", handleUpload)
	http.HandleFunc("/scans/", handleGetScan)

	fmt.Println("Mock Armis API Server running on http://localhost:8080")
	server := &http.Server{
		Addr:         ":8080",
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Missing authorization header", http.StatusUnauthorized)
		return
	}

	_, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Missing file in request", http.StatusBadRequest)
		return
	}

	scanID := fmt.Sprintf("scan-%d", time.Now().Unix())

	startTime := time.Now()
	result := &ScanResult{
		ScanID:    scanID,
		Status:    "completed",
		StartedAt: startTime,
		EndedAt:   startTime.Add(5 * time.Second),
		Findings: []Finding{
			{
				ID:          "VULN-001",
				Type:        "VULNERABILITY",
				Severity:    "CRITICAL",
				Title:       "SQL Injection vulnerability",
				Description: "Potential SQL injection in user input handling",
				File:        "src/database/query.go",
				Line:        42,
				Column:      15,
				CWE:         "CWE-89",
			},
			{
				ID:          "SCA-001",
				Type:        "SCA",
				Severity:    "HIGH",
				Title:       "Vulnerable dependency: lodash",
				Description: "lodash version 4.17.15 has known vulnerabilities",
				Package:     "lodash",
				Version:     "4.17.15",
				FixVersion:  "4.17.21",
				CVE:         "CVE-2021-23337",
			},
			{
				ID:          "SECRET-001",
				Type:        "SECRET",
				Severity:    "CRITICAL",
				Title:       "AWS Access Key exposed",
				Description: "AWS access key found in source code",
				File:        "config/aws.go",
				Line:        10,
			},
			{
				ID:          "LICENSE-001",
				Type:        "LICENSE",
				Severity:    "MEDIUM",
				Title:       "GPL license detected",
				Description: "GPL-3.0 license may have compliance implications",
				Package:     "some-gpl-package",
				Version:     "1.0.0",
			},
			{
				ID:          "VULN-002",
				Type:        "VULNERABILITY",
				Severity:    "LOW",
				Title:       "Weak cryptographic algorithm",
				Description: "Use of MD5 hash function detected",
				File:        "src/crypto/hash.go",
				Line:        25,
				CWE:         "CWE-327",
			},
		},
		Summary: Summary{
			Total: 5,
			BySeverity: map[string]int{
				"CRITICAL": 2,
				"HIGH":     1,
				"MEDIUM":   1,
				"LOW":      1,
				"INFO":     0,
			},
			ByType: map[string]int{
				"VULNERABILITY": 2,
				"SCA":           1,
				"SECRET":        1,
				"LICENSE":       1,
			},
		},
	}

	scans[scanID] = result

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ScanResponse{ScanID: scanID})
}

func handleGetScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	scanID := r.URL.Path[len("/scans/"):]
	if scanID == "" {
		http.Error(w, "Scan ID required", http.StatusBadRequest)
		return
	}

	result, exists := scans[scanID]
	if !exists {
		http.Error(w, "Scan not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}
