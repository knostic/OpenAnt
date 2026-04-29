// Package git provides git helpers for PR-diff / incremental scanning.
//
// It computes a diff_manifest.json that the Python core reads to filter the
// pipeline to units whose bodies overlap the diff between a base ref and HEAD.
package git

import (
	"encoding/json"
	"fmt"
	"os"
)

// Scope values for Manifest.Scope.
const (
	ScopeChangedFiles     = "changed_files"
	ScopeChangedFunctions = "changed_functions"
	ScopeCallers          = "callers"
)

// IsValidScope reports whether s is one of the three supported scopes.
func IsValidScope(s string) bool {
	return s == ScopeChangedFiles || s == ScopeChangedFunctions || s == ScopeCallers
}

// Manifest is the on-disk contract between the Go CLI (producer) and the
// Python core (consumer). Written to <scan_dir>/diff_manifest.json.
//
// Hunks is omitted for the ScopeChangedFiles scope (not needed). Each value
// in Hunks is a slice of [start_line, end_line] pairs on the new side
// (inclusive). Pure-deletion hunks are dropped at build time.
type Manifest struct {
	BaseRef      string          `json:"base_ref"`
	BaseSHA      string          `json:"base_sha"`
	HeadSHA      string          `json:"head_sha"`
	Scope        string          `json:"scope"`
	PRNumber     int             `json:"pr_number,omitempty"`
	ChangedFiles []string        `json:"changed_files"`
	Hunks        map[string][][2]int `json:"hunks,omitempty"`
}

// WriteManifest writes m to path as indented JSON.
func WriteManifest(path string, m *Manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write manifest %s: %w", path, err)
	}
	return nil
}

// ReadManifest reads and parses a manifest from path. Primarily used by tests.
func ReadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest %s: %w", path, err)
	}
	return &m, nil
}
