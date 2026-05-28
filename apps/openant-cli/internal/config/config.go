// Package config handles persistent configuration for the OpenAnt CLI.
//
// Configuration is stored in ~/.config/openant/config.json (or
// $XDG_CONFIG_HOME/openant/config.json on Linux). The file is created
// with 0600 permissions since it may contain API keys.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Config holds the persistent CLI configuration.
type Config struct {
	APIKey        string `json:"api_key,omitempty"`
	DefaultModel  string `json:"default_model,omitempty"`
	ActiveProject string `json:"active_project,omitempty"`
}

// configDir returns the base directory for openant config files.
// On macOS/Linux: $XDG_CONFIG_HOME/openant or ~/.config/openant
// On Windows: %APPDATA%\openant
func configDir() (string, error) {
	// Use Go's built-in UserConfigDir which handles platform differences:
	//   macOS:   ~/Library/Application Support
	//   Linux:   $XDG_CONFIG_HOME or ~/.config
	//   Windows: %APPDATA%
	//
	// However, on macOS we prefer ~/.config for CLI tools (standard for
	// developer tools like gh, docker, aws). UserConfigDir returns
	// ~/Library/Application Support which is more for GUI apps.
	if runtime.GOOS != "windows" {
		if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
			return filepath.Join(xdg, "openant"), nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot determine home directory: %w", err)
		}
		return filepath.Join(home, ".config", "openant"), nil
	}

	// Windows: use %APPDATA%
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine config directory: %w", err)
	}
	return filepath.Join(dir, "openant"), nil
}

// Path returns the full path to the config file.
func Path() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

// Load reads the config file. Returns an empty Config if the file
// does not exist (not an error — first run).
func Load() (*Config, error) {
	path, err := Path()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Config{}, nil
		}
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config at %s: %w", path, err)
	}

	return &cfg, nil
}

// Save writes the config to disk with restricted permissions.
func Save(cfg *Config) error {
	path, err := Path()
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize config: %w", err)
	}
	data = append(data, '\n')

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	// os.WriteFile only applies the mode when it CREATES the file; a pre-existing config
	// may hold an API key under looser permissions, so enforce 0600 explicitly (CWE-732).
	if err := os.Chmod(path, 0600); err != nil {
		return fmt.Errorf("failed to restrict config permissions: %w", err)
	}

	return nil
}

// ResolveAPIKey returns the API key using the precedence:
//
//	flag > config file
//
// Environment variables and .env files are intentionally NOT checked.
// Users must explicitly configure their key via `openant set-api-key`
// or pass it with --api-key.
//
// Returns empty string if no key is found.
func ResolveAPIKey(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}

	cfg, err := Load()
	if err != nil {
		return ""
	}
	return cfg.APIKey
}

// DataDir returns the root data directory: ~/.openant/
func DataDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".openant"), nil
}

// ProjectsDir returns ~/.openant/projects/
func ProjectsDir() (string, error) {
	dataDir, err := DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dataDir, "projects"), nil
}

// ProjectDir returns the directory for a specific project.
// Name is "org/repo", so the path is ~/.openant/projects/org/repo/
func ProjectDir(name string) (string, error) {
	projDir, err := ProjectsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(projDir, name), nil
}

// ScanDir returns the scan directory for a specific project, commit SHA, and language.
// ~/.openant/projects/org/repo/scans/{shortSHA}/{language}/
func ScanDir(projectName, shortSHA, language string) (string, error) {
	projDir, err := ProjectDir(projectName)
	if err != nil {
		return "", err
	}
	return filepath.Join(projDir, "scans", shortSHA, language), nil
}

// MaskKey returns a masked version of an API key for display.
// Shows the first 7 and last 4 characters.
func MaskKey(key string) string {
	if key == "" {
		return "(not set)"
	}
	if len(key) <= 12 {
		return key[:3] + "..." + key[len(key)-2:]
	}
	return key[:7] + "..." + key[len(key)-4:]
}
