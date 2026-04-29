// Package agentdetect detects AI coding agents installed on the system.
package agentdetect

import (
	"fmt"
	"os"
)

// DetectedAgent represents a single detected agent for a specific user.
type DetectedAgent struct {
	Name         string `json:"name"`
	MCPInstalled bool   `json:"mcp_installed"`
	Version      string `json:"version,omitempty"`
	User         string `json:"user"`
}

// UserResult groups detected agents by user.
type UserResult struct {
	User   string
	Agents []DetectedAgent
}

// ScanResult is the aggregate result of scanning all user profiles.
type ScanResult struct {
	Users []UserResult
}

// FlatResults returns all DetectedAgent entries in a flat slice (for JSON output).
func (r *ScanResult) FlatResults() []DetectedAgent {
	var results []DetectedAgent
	for _, u := range r.Users {
		results = append(results, u.Agents...)
	}
	return results
}

// Scanner performs agent detection across user profiles.
type Scanner struct {
	platform  Platform
	detectors []AgentDetector
}

// NewScanner creates a Scanner with the given platform and all registered detectors.
func NewScanner(platform Platform) *Scanner {
	return &Scanner{
		platform:  platform,
		detectors: Registry(),
	}
}

// Scan performs agent detection across all accessible user profiles.
func (s *Scanner) Scan() (*ScanResult, error) {
	users, err := s.platform.UserHomeDirs()
	if err != nil {
		return nil, fmt.Errorf("enumerating user profiles: %w", err)
	}

	result := &ScanResult{}
	for _, user := range users {
		resolvedHome, err := resolvePath(user.HomeDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping user %s: %v\n", user.Username, err)
			continue
		}

		userResult := UserResult{User: user.Username}
		for _, detector := range s.detectors {
			if !detector.Detect(resolvedHome, user.HomeDir, s.platform) {
				continue
			}
			agent := DetectedAgent{
				Name:         string(detector.Name()),
				MCPInstalled: detector.CheckMCP(resolvedHome, user.HomeDir, s.platform),
				Version:      detector.DetectVersion(resolvedHome, user.HomeDir, s.platform),
				User:         user.Username,
			}
			userResult.Agents = append(userResult.Agents, agent)
		}
		if len(userResult.Agents) > 0 {
			result.Users = append(result.Users, userResult)
		}
	}

	return result, nil
}
