// Package config loads collector configuration from a JSON file.
package config

import (
	"encoding/json"
	"os"
)

// Config mirrors inventory.config.json.
type Config struct {
	Endpoint         string `json:"endpoint"`
	APIKey           string `json:"apiKey"`
	Profile          string `json:"profile"`
	IncludeAppx      bool   `json:"includeAppx"`
	IncludeProcesses bool   `json:"includeProcesses"`
	Compress         bool   `json:"compress"`
	Delta            bool   `json:"delta"`
	ChunkBytes       int    `json:"chunkBytes"`
	MaxRetries       int    `json:"maxRetries"`
	MaxListItems     int    `json:"maxListItems"`
	MaxPayloadBytes  int64  `json:"maxPayloadBytes"`
	Proxy            string `json:"proxy"`
	StatePath        string `json:"statePath"`
	OutputPath       string `json:"outputPath"`
	DryRun           bool   `json:"dryRun"`
}

// Defaults returns the built-in configuration.
func Defaults() Config {
	return Config{
		Profile:         "full",
		ChunkBytes:      900000,
		MaxRetries:      4,
		MaxListItems:    2000,
		MaxPayloadBytes: 1500000,
	}
}

// Load reads a config file, falling back to defaults when path is empty or
// missing. Explicit zero values are not overridden by defaults for booleans;
// numeric defaults are preserved by starting from Defaults().
func Load(path string) (Config, error) {
	cfg := Defaults()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	applyDefaults(&cfg)
	return cfg, nil
}

func applyDefaults(c *Config) {
	d := Defaults()
	if c.Profile == "" {
		c.Profile = d.Profile
	}
	if c.ChunkBytes <= 0 {
		c.ChunkBytes = d.ChunkBytes
	}
	if c.MaxRetries <= 0 {
		c.MaxRetries = d.MaxRetries
	}
	if c.MaxListItems <= 0 {
		c.MaxListItems = d.MaxListItems
	}
	if c.MaxPayloadBytes <= 0 {
		c.MaxPayloadBytes = d.MaxPayloadBytes
	}
}

// Level maps a profile name to a numeric collection level.
func Level(profile string) int {
	switch profile {
	case "minimal":
		return 0
	case "quick":
		return 1
	default:
		return 2
	}
}
