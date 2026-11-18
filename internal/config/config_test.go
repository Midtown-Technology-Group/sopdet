package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadToleratesUTF8BOM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bom.json")
	body := append([]byte("\xef\xbb\xbf"), []byte(`{"profile":"full","maxPayloadBytes":20000000}`)...)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("BOM config should load: %v", err)
	}
	if cfg.Profile != "full" || cfg.MaxPayloadBytes != 20000000 {
		t.Fatalf("bad config: %+v", cfg)
	}
}

func TestLoadMissingReturnsDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Profile != Defaults().Profile {
		t.Fatalf("expected defaults: %+v", cfg)
	}
}

func TestLoadAPIKeyFromEnvironment(t *testing.T) {
	t.Setenv("SOPDET_API_KEY", "environment-key")
	path := filepath.Join(t.TempDir(), "inventory.config.json")
	if err := os.WriteFile(path, []byte(`{"apiKey":"file-key"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIKey != "environment-key" {
		t.Fatalf("expected environment key to override file value, got %q", cfg.APIKey)
	}
}
