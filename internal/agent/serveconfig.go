// Package agent implements sopdet's resident serve mode: enroll, hold a
// device key, and (from later milestones) claim and run ad-hoc PowerShell
// jobs from Bifrost. Inventory mode is unchanged.
package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ServeConfig is the fully resolved configuration for `-serve`.
// Precedence when resolving: flags > environment > serve config file.
//
// The WebSocket hint path is on by default. For the M6.3 poll-only drill
// (Midtown-Technology-Group/bifrost#852) set the environment variable
// SOPDET_DISABLE_HINTS to a truthy value (`1`, `true`, `yes`, `on`,
// case-insensitive): ResolveServeConfig then resolves EnableHints to false
// and the agent claims over the HTTP poll alone.
type ServeConfig struct {
	// BifrostURL is the base URL of the Bifrost instance (https://...).
	BifrostURL string
	// DeviceKey is the raw bfdk_ device key. Secret: never log or print it.
	DeviceKey string
	// EnrollmentToken is a single-use bfen_ token minted by the operator.
	// Secret: never log or print it.
	EnrollmentToken string
	// StatePath is where the device key is persisted after enrollment.
	StatePath string
	// PollInterval is the HTTP claim poll interval used while the WebSocket
	// hint channel is down.
	PollInterval time.Duration
	// WorkDir is the working directory for per-job temp script files.
	WorkDir string
	// AgentVersion is the build version reported on every heartbeat (the
	// platform's `agent_version` device column, String(64)). It is wired
	// from main.Version (ldflag-overridden at build time), so it is not
	// operator-configurable: the config-file layer cannot carry it and only
	// the flag layer passes it through resolution.
	AgentVersion string
	// EnableHints selects the WebSocket hint channel; the struct doc records
	// the SOPDET_DISABLE_HINTS poll-only drill knob that resolves it false.
	EnableHints bool
}

// serveFile mirrors the optional JSON serve config file (camelCase, matching
// the inventory config style).
type serveFile struct {
	BifrostURL      string `json:"bifrostUrl"`
	DeviceKey       string `json:"deviceKey"`
	EnrollmentToken string `json:"enrollmentToken"`
	StatePath       string `json:"statePath"`
	PollInterval    string `json:"pollInterval"` // Go duration, e.g. "10s"
	WorkDir         string `json:"workDir"`
}

// DefaultServePollInterval matches the M0 protocol freeze: agents poll for
// claims every 10s when no pending job shortens the hint (5s server-side).
const DefaultServePollInterval = 10 * time.Second

// LoadServeConfig reads an optional serve config JSON file. An empty path,
// or a missing file at an explicit path, is an error only for explicit
// paths that do not exist; empty path returns defaults (zero values).
func LoadServeConfig(path string) (ServeConfig, error) {
	if path == "" {
		return ServeConfig{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ServeConfig{}, fmt.Errorf("serve config: %w", err)
	}
	var raw serveFile
	if err := json.Unmarshal(data, &raw); err != nil {
		return ServeConfig{}, fmt.Errorf("serve config: %w", err)
	}
	cfg := ServeConfig{
		BifrostURL:      raw.BifrostURL,
		DeviceKey:       raw.DeviceKey,
		EnrollmentToken: raw.EnrollmentToken,
		StatePath:       raw.StatePath,
		WorkDir:         raw.WorkDir,
	}
	if raw.PollInterval != "" {
		d, err := time.ParseDuration(raw.PollInterval)
		if err != nil {
			return ServeConfig{}, fmt.Errorf("serve config pollInterval: %w", err)
		}
		cfg.PollInterval = d
	}
	return cfg, nil
}

// ResolveServeConfig layers configuration with precedence
// file < environment < flags (zero-value flags are "unset").
func ResolveServeConfig(
	file ServeConfig,
	flags ServeConfig,
	getenv func(string) string,
) ServeConfig {
	out := file

	if v := getenv("SOPDET_BIFROST_URL"); v != "" {
		out.BifrostURL = v
	}
	if v := getenv("SOPDET_DEVICE_KEY"); v != "" {
		out.DeviceKey = v
	}
	if v := getenv("SOPDET_ENROLLMENT_TOKEN"); v != "" {
		out.EnrollmentToken = v
	}
	if v := getenv("SOPDET_SERVE_STATE"); v != "" {
		out.StatePath = v
	}
	if v := getenv("SOPDET_WORK_DIR"); v != "" {
		out.WorkDir = v
	}
	if v := getenv("SOPDET_POLL_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			out.PollInterval = d
		}
	}
	// M6.3 poll-only drill knob (Midtown-Technology-Group/bifrost#852):
	// a truthy SOPDET_DISABLE_HINTS turns the WebSocket hint path off so
	// claims flow through the HTTP poll alone. Hints are on unless the
	// drill is explicitly requested.
	out.EnableHints = !truthyEnv(getenv("SOPDET_DISABLE_HINTS"))

	if flags.BifrostURL != "" {
		out.BifrostURL = flags.BifrostURL
	}
	if flags.DeviceKey != "" {
		out.DeviceKey = flags.DeviceKey
	}
	if flags.EnrollmentToken != "" {
		out.EnrollmentToken = flags.EnrollmentToken
	}
	if flags.StatePath != "" {
		out.StatePath = flags.StatePath
	}
	if flags.WorkDir != "" {
		out.WorkDir = flags.WorkDir
	}
	if flags.PollInterval > 0 {
		out.PollInterval = flags.PollInterval
	}
	if flags.AgentVersion != "" {
		out.AgentVersion = flags.AgentVersion
	}
	return out
}

// truthyEnv reports whether a drill-style environment knob selects "on":
// 1, true, yes, or on (case-insensitive, surrounding space ignored).
// Anything else — including an unset variable — is off.
func truthyEnv(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// ApplyServeDefaults fills zero-value fields with their M0 defaults.
func ApplyServeDefaults(cfg *ServeConfig) {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = DefaultServePollInterval
	}
	if cfg.StatePath == "" {
		cfg.StatePath = DefaultStatePath()
	}
}

// DefaultStatePath is the per-user persisted device state location.
// On Windows the M5 installer additionally applies a SYSTEM/Administrators
// DACL; on POSIX SaveDeviceState writes mode 0600.
func DefaultStatePath() string {
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "sopdet", "serve.json")
	}
	return filepath.Join(".", "sopdet-serve.json")
}
