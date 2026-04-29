package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Scan kinds. A scan-run is one of these.
const (
	ScanKindFull = "full"
	ScanKindDiff = "diff"
)

// Scan statuses. Lifecycle: running → (success | failed | interrupted).
const (
	ScanStatusRunning     = "running"
	ScanStatusSuccess     = "success"
	ScanStatusFailed      = "failed"
	ScanStatusInterrupted = "interrupted"
)

// scanMetaFilename is the filename written into each scan-run dir.
const scanMetaFilename = "meta.json"

// DiffStats summarizes how many units the diff filter selected for analysis.
// Populated by the parse step when a diff manifest is present.
type DiffStats struct {
	UnitsSelected int `json:"units_selected"`
	UnitsTotal    int `json:"units_total"`
}

// ScanMeta describes a single scan-run. One file per scan-run dir at
// ~/.openant/projects/<name>/scans/<short_sha>/meta.json.
//
// The dir is the source of truth for "what scans exist on this project";
// project.json carries only static identity. To find the latest run, walk
// scans/, read each meta.json, sort by StartedAt.
type ScanMeta struct {
	Kind            string     `json:"kind"`             // ScanKindFull or ScanKindDiff
	Commit          string     `json:"commit"`           // full SHA scanned
	Branch          string     `json:"branch,omitempty"` // best-effort, may be empty for detached HEAD
	StartedAt       string     `json:"started_at"`       // RFC3339
	FinishedAt      string     `json:"finished_at,omitempty"`
	Status          string     `json:"status"`
	Language        string     `json:"language"`
	AnalyzerVersion string     `json:"analyzer_version,omitempty"`
	Model           string     `json:"model,omitempty"`
	Base            string     `json:"base,omitempty"`  // diff base SHA, only when Kind == ScanKindDiff
	Scope           string     `json:"scope,omitempty"` // diff scope, only when Kind == ScanKindDiff
	DiffStats       *DiffStats `json:"diff_stats,omitempty"`
}

// ScanRunDir returns the per-run directory (without the language subdir).
// ~/.openant/projects/<name>/scans/<short_sha>/
//
// meta.json lives here. Language-specific dataset/report output continues
// to live at <run-dir>/<language>/ via ScanDir.
func ScanRunDir(projectName, shortSHA string) (string, error) {
	projDir, err := ProjectDir(projectName)
	if err != nil {
		return "", err
	}
	return filepath.Join(projDir, "scans", shortSHA), nil
}

// scanMetaPath returns the path to meta.json for a given run.
func scanMetaPath(projectName, shortSHA string) (string, error) {
	runDir, err := ScanRunDir(projectName, shortSHA)
	if err != nil {
		return "", err
	}
	return filepath.Join(runDir, scanMetaFilename), nil
}

// SaveScanMeta writes meta.json atomically (temp + rename) into the run dir.
// Creates the run dir if missing.
func SaveScanMeta(projectName, shortSHA string, m *ScanMeta) error {
	runDir, err := ScanRunDir(projectName, shortSHA)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return fmt.Errorf("create scan run dir: %w", err)
	}

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize scan meta: %w", err)
	}
	data = append(data, '\n')

	finalPath := filepath.Join(runDir, scanMetaFilename)
	tmp, err := os.CreateTemp(runDir, scanMetaFilename+".tmp.*")
	if err != nil {
		return fmt.Errorf("create temp meta file: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write temp meta file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp meta file: %w", err)
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename meta file: %w", err)
	}
	return nil
}

// LoadScanMeta reads meta.json for a given run. Returns os.ErrNotExist
// (wrapped) when missing — callers can treat that as "legacy / no meta".
func LoadScanMeta(projectName, shortSHA string) (*ScanMeta, error) {
	path, err := scanMetaPath(projectName, shortSHA)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("scan meta not found at %s: %w", path, err)
		}
		return nil, fmt.Errorf("read scan meta: %w", err)
	}
	var m ScanMeta
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse scan meta at %s: %w", path, err)
	}
	return &m, nil
}

// LatestScanMeta walks scans/ for the project and returns the most recent
// run that has a parseable meta.json with status == success. Returns
// (nil, "", nil) when no qualifying run exists (no scans dir, all dirs are
// legacy / missing meta, or all runs failed).
//
// shortSHA returned is the directory name, useful for callers that want to
// reference the run dir.
//
// Failed/interrupted runs are skipped — they are not a valid baseline.
// The recap UI may surface them separately in the future; baseline
// resolution does not.
func LatestScanMeta(projectName string) (*ScanMeta, string, error) {
	projDir, err := ProjectDir(projectName)
	if err != nil {
		return nil, "", err
	}
	scansDir := filepath.Join(projDir, "scans")
	entries, err := os.ReadDir(scansDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, "", nil
		}
		return nil, "", fmt.Errorf("list scans dir: %w", err)
	}

	type candidate struct {
		shortSHA string
		meta     *ScanMeta
		ts       time.Time
	}
	var candidates []candidate
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		m, err := LoadScanMeta(projectName, e.Name())
		if err != nil {
			// Missing or malformed — treat as legacy and skip.
			continue
		}
		if m.Status != ScanStatusSuccess {
			continue
		}
		ts, err := time.Parse(time.RFC3339, m.StartedAt)
		if err != nil {
			continue
		}
		candidates = append(candidates, candidate{shortSHA: e.Name(), meta: m, ts: ts})
	}
	if len(candidates) == 0 {
		return nil, "", nil
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].ts.After(candidates[j].ts)
	})
	top := candidates[0]
	return top.meta, top.shortSHA, nil
}

// NewScanMeta builds a ScanMeta for a freshly-started run, with
// StartedAt set to now and Status set to running.
func NewScanMeta(kind, commit, branch, language string) *ScanMeta {
	return &ScanMeta{
		Kind:      kind,
		Commit:    commit,
		Branch:    branch,
		StartedAt: time.Now().UTC().Format(time.RFC3339),
		Status:    ScanStatusRunning,
		Language:  language,
	}
}

// FinalizeScanMeta loads the meta for a run, sets its terminal status and
// FinishedAt to now, and saves. No-ops (returning nil) when meta.json does
// not exist — callers may invoke this on legacy runs or ad-hoc scans where
// no meta was ever written.
func FinalizeScanMeta(projectName, shortSHA, status string) error {
	m, err := LoadScanMeta(projectName, shortSHA)
	if err != nil {
		// Treat missing meta as a no-op so ad-hoc scans don't error here.
		return nil
	}
	m.Status = status
	m.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	return SaveScanMeta(projectName, shortSHA, m)
}
