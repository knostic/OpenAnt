package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Scanner finds all Go source files in a repository
type Scanner struct {
	repoPath    string
	excludeDirs map[string]bool
	skipTests   bool
}

// NewScanner creates a new scanner for the given repository path
func NewScanner(repoPath string, skipTests bool) *Scanner {
	excludeDirs := map[string]bool{
		"vendor":       true,
		"testdata":     true,
		".git":         true,
		".svn":         true,
		".hg":          true,
		"node_modules": true,
		"__pycache__":  true,
		".idea":        true,
		".vscode":      true,
		"dist":         true,
		"build":        true,
		"bin":          true,
		".cache":       true,
	}

	return &Scanner{
		repoPath:    repoPath,
		excludeDirs: excludeDirs,
		skipTests:   skipTests,
	}
}

// Scan walks the repository and returns all Go source files
func (s *Scanner) Scan() (*ScanResult, error) {
	result := &ScanResult{
		Repository: s.repoPath,
		ScanTime:   time.Now().Format(time.RFC3339),
		Files:      []FileInfo{},
		Statistics: ScanStatistics{
			ByExtension: make(map[string]int),
		},
	}

	dirsScanned := 0
	dirsExcluded := 0
	symlinksSkipped := 0
	dirsUnreadable := 0
	symlinkExamples := []string{}
	unreadableExamples := []string{}

	err := filepath.Walk(s.repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// A directory we cannot read is a coverage gap, not a non-event.
			// Record it (bounded) instead of silently swallowing — a silent
			// skip is a false negative, the worst failure direction for a SAST
			// tool. Return nil to keep walking the rest of the tree.
			dirsUnreadable++
			if len(unreadableExamples) < 5 {
				rel, relErr := filepath.Rel(s.repoPath, path)
				if relErr != nil {
					rel = path
				}
				unreadableExamples = append(unreadableExamples, fmt.Sprintf("%s: %v", rel, err))
			}
			return nil
		}

		// Get relative path from repo root
		relPath, err := filepath.Rel(s.repoPath, path)
		if err != nil {
			relPath = path
		}

		// Refuse every symlink (file OR directory) inside the repository. The
		// scanned repo is untrusted: filepath.Walk lstat's each entry, so a
		// symlinked file `leak.go -> /outside/secret` has IsDir()==false and a
		// .go extension and would otherwise be added and read THROUGH the link,
		// exfiltrating host files into dataset.json (and thence to the model
		// provider) — the same hole core/repo_walk.py closes for the Python
		// family. The repo root itself is exempt (path != s.repoPath): the
		// threat is attacker-committed links INSIDE the repo, not an operator
		// choosing a symlinked path to scan (matching the Python walker, which
		// applies the guard to entries, never the root). Return nil, never
		// SkipDir: on a non-directory SkipDir would skip the rest of the parent
		// directory, dropping sibling real files.
		if path != s.repoPath && info.Mode()&os.ModeSymlink != 0 {
			symlinksSkipped++
			if len(symlinkExamples) < 5 {
				symlinkExamples = append(symlinkExamples, relPath)
			}
			return nil
		}

		// Skip excluded directories
		if info.IsDir() {
			dirName := filepath.Base(path)

			// Skip hidden directories (start with .)
			if strings.HasPrefix(dirName, ".") && dirName != "." {
				dirsExcluded++
				return filepath.SkipDir
			}

			// Skip directories starting with _
			if strings.HasPrefix(dirName, "_") {
				dirsExcluded++
				return filepath.SkipDir
			}

			// Skip excluded directory names
			if s.excludeDirs[dirName] {
				dirsExcluded++
				return filepath.SkipDir
			}

			dirsScanned++
			return nil
		}

		// Only process .go files
		ext := filepath.Ext(path)
		if ext != ".go" {
			return nil
		}

		// Optionally skip test files
		if s.skipTests && strings.HasSuffix(info.Name(), "_test.go") {
			return nil
		}

		// Add file to results
		result.Files = append(result.Files, FileInfo{
			Path:      relPath,
			Size:      info.Size(),
			Extension: ext,
		})

		// Update statistics
		result.Statistics.TotalFiles++
		result.Statistics.ByExtension[ext]++
		result.Statistics.TotalSizeBytes += info.Size()

		return nil
	})

	if err != nil {
		return nil, err
	}

	result.Statistics.DirectoriesScanned = dirsScanned
	result.Statistics.DirectoriesExcluded = dirsExcluded
	result.Statistics.SymlinksSkipped = symlinksSkipped
	result.Statistics.SymlinkExamples = symlinkExamples
	result.Statistics.DirectoriesUnreadable = dirsUnreadable
	result.Statistics.UnreadableExamples = unreadableExamples

	return result, nil
}

// GetFilePaths returns just the file paths for downstream processing
func (s *Scanner) GetFilePaths(result *ScanResult) []string {
	paths := make([]string, len(result.Files))
	for i, f := range result.Files {
		paths[i] = filepath.Join(s.repoPath, f.Path)
	}
	return paths
}
