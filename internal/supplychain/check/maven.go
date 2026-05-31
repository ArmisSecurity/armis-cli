package check

import (
	"encoding/xml"
	"fmt"
	"os"
	"strings"
)

type pomProject struct {
	XMLName      xml.Name      `xml:"project"`
	Dependencies pomDeps       `xml:"dependencies"`
	DepMgmt      pomDepMgmt    `xml:"dependencyManagement"`
}

type pomDepMgmt struct {
	Dependencies pomDeps `xml:"dependencies"`
}

type pomDeps struct {
	Dependency []pomDependency `xml:"dependency"`
}

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

// ParseMavenDeps parses a pom.xml file for direct dependencies with explicit versions.
func ParseMavenDeps(path string) ([]PackageEntry, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path from lockfile detection
	if err != nil {
		return nil, fmt.Errorf("reading pom.xml: %w", err)
	}

	var project pomProject
	if err := xml.Unmarshal(data, &project); err != nil {
		return nil, fmt.Errorf("parsing pom.xml: %w", err)
	}

	var entries []PackageEntry
	seen := make(map[string]bool)

	for _, dep := range project.Dependencies.Dependency {
		entry := mavenDepToEntry(dep)
		if entry != nil && !seen[entry.Name+"@"+entry.Version] {
			seen[entry.Name+"@"+entry.Version] = true
			entries = append(entries, *entry)
		}
	}

	for _, dep := range project.DepMgmt.Dependencies.Dependency {
		entry := mavenDepToEntry(dep)
		if entry != nil && !seen[entry.Name+"@"+entry.Version] {
			seen[entry.Name+"@"+entry.Version] = true
			entries = append(entries, *entry)
		}
	}

	return entries, nil
}

func mavenDepToEntry(dep pomDependency) *PackageEntry {
	if dep.GroupID == "" || dep.ArtifactID == "" || dep.Version == "" {
		return nil
	}

	// Skip property references that can't be resolved
	if strings.Contains(dep.Version, "${") {
		return nil
	}

	// Skip test and provided scope
	scope := strings.ToLower(dep.Scope)
	if scope == "test" || scope == "provided" {
		return nil
	}

	return &PackageEntry{
		Name:    dep.GroupID + ":" + dep.ArtifactID,
		Version: dep.Version,
	}
}
