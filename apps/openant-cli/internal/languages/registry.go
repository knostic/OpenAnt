// Package languages is the Go-side reader for config/languages.json, the
// single source of truth for which languages OpenAnt supports.
//
// This package exists so that flag help text is DERIVED from config rather
// than hardcoded. Previously each of cmd/init.go, cmd/scan.go and cmd/parse.go
// carried its own literal list, and scan.go/parse.go silently fell behind when
// Zig was added — nothing failed, so nobody noticed.
//
// The Python side reads the same file via libs/openant-core/core/language_registry.py.
//
// NOTE: the two detectors are NOT yet pinned to each other by a shared
// fixture. Each has its own tests over its own temp trees, so a semantic
// divergence (skip-dir pruning, case-folding, tie-breaking) would not be
// caught. A cross-language golden fixture is the missing control here.
package languages

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// parserSpec mirrors the per-language "parser" object in config/languages.json.
type parserSpec struct {
	Mode      string `json:"mode"`
	Script    string `json:"script"`
	Bootstrap string `json:"bootstrap"`
}

// languageSpec mirrors one entry of the "languages" object.
type languageSpec struct {
	Extensions     []string   `json:"extensions"`
	Parser         parserSpec `json:"parser"`
	DockerTemplate *string    `json:"docker_template"`
	Enabled        bool       `json:"enabled"`
}

// Config is the parsed form of config/languages.json.
//
// SkipDirs and Extensions are the legacy flat maps, kept byte-compatible
// because both this reader and the Python one consume them. Languages is the
// richer per-language block; a Python-side consistency test asserts the flat
// Extensions map stays exactly the union of the per-language lists.
type Config struct {
	SkipDirs   []string                `json:"skip_dirs"`
	Extensions map[string]string       `json:"extensions"`
	Languages  map[string]languageSpec `json:"languages"`
}

// FindConfig locates config/languages.json by walking up from the executable
// path and then the current working directory.
func FindConfig() (string, error) {
	rel := filepath.Join("config", "languages.json")

	// Strategy 1: walk up from the executable.
	if exePath, err := os.Executable(); err == nil {
		exePath, _ = filepath.EvalSymlinks(exePath)
		dir := filepath.Dir(exePath)
		for range 6 {
			candidate := filepath.Join(dir, rel)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate, nil
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}

	// Strategy 2: walk up from CWD.
	if cwd, err := os.Getwd(); err == nil {
		dir := cwd
		for range 6 {
			candidate := filepath.Join(dir, rel)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate, nil
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}

	return "", fmt.Errorf("could not find config/languages.json from executable or working directory")
}

// Load reads and parses the shared language config.
func Load() (*Config, error) {
	path, err := FindConfig()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", path, err)
	}
	return &cfg, nil
}

// Supported returns the enabled language names, sorted.
func Supported() ([]string, error) {
	cfg, err := Load()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(cfg.Languages))
	for name, spec := range cfg.Languages {
		if spec.Enabled {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

// FlagHelp renders the --language flag help string from config.
//
// Every cobra command that exposes --language must call this rather than
// writing its own list. If the config cannot be read we degrade to a generic
// string instead of failing: flag registration happens during init and a hard
// error there would make the whole CLI unusable over a config problem that
// only affects help text.
func FlagHelp() string {
	names, err := Supported()
	if err != nil || len(names) == 0 {
		return "Language to analyze (see config/languages.json), or auto to detect"
	}
	return fmt.Sprintf(
		"Language: %s, auto (default; auto = detect and scan every language present)",
		strings.Join(names, ", "),
	)
}

// DetectLanguages walks a repository and returns the source-file count per
// language.
//
// This is the multi-language primitive; DetectLanguage wraps it for the
// single-language callers. Directories named in skip_dirs are PRUNED (not just
// filtered), which the Python implementation mirrors via os.walk so both sides
// agree on what "skip" means.
func DetectLanguages(repoPath string) (map[string]int, error) {
	cfg, err := Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load language config: %w", err)
	}

	skipDirs := make(map[string]bool, len(cfg.SkipDirs))
	for _, d := range cfg.SkipDirs {
		skipDirs[d] = true
	}

	counts := make(map[string]int)

	err = filepath.WalkDir(repoPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip inaccessible paths
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(d.Name()))
		if lang, ok := cfg.Extensions[ext]; ok {
			counts[lang]++
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to walk repository: %w", err)
	}

	return counts, nil
}

// Ranked returns languages ordered by descending file count, ties broken
// alphabetically.
//
// The tie-break is not cosmetic. Go map iteration order is randomized, so the
// previous "keep the first strictly-greater count" loop returned an ARBITRARY
// winner on a tie — and could disagree with Python's max() on the same repo,
// across runs. Sorting makes both sides deterministic and identical.
func Ranked(counts map[string]int) []string {
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		if counts[names[i]] != counts[names[j]] {
			return counts[names[i]] > counts[names[j]]
		}
		return names[i] < names[j]
	})
	return names
}

// DetectLanguage returns the dominant language by file count.
//
// Behaviour is preserved from the original cmd/init.go implementation, except
// that ties are now resolved deterministically (see Ranked).
func DetectLanguage(repoPath string) (string, error) {
	counts, err := DetectLanguages(repoPath)
	if err != nil {
		return "", err
	}

	ranked := Ranked(counts)
	if len(ranked) == 0 {
		supported, sErr := Supported()
		list := "Python, JavaScript/TypeScript, Go, C/C++, Ruby, PHP, Zig"
		if sErr == nil && len(supported) > 0 {
			list = strings.Join(supported, ", ")
		}
		return "", fmt.Errorf(
			"no supported source files found in %s. Supported languages: %s",
			repoPath, list,
		)
	}

	return ranked[0], nil
}
