//go:build linux

package collect

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Midtown-Technology-Group/sopdet/internal/schema"
)

func TestCollectLinuxSoftwareSurfacesOperationalSourceError(t *testing.T) {
	denied := errors.New("permission denied")
	records, err := collectLinuxSoftware([]softwareSource{
		{"missing", func() ([]schema.Record, error) { return nil, os.ErrNotExist }},
		{"blocked", func() ([]schema.Record, error) { return nil, denied }},
	})
	if len(records) != 0 || !errors.Is(err, denied) || !strings.Contains(err.Error(), "blocked inventory") {
		t.Fatalf("operational source error was suppressed: records=%v err=%v", records, err)
	}
}

func TestCollectLinuxSoftwareAcceptsAvailableSource(t *testing.T) {
	want := []schema.Record{{"key": "pkg|1"}}
	records, err := collectLinuxSoftware([]softwareSource{
		{"missing", func() ([]schema.Record, error) { return nil, os.ErrNotExist }},
		{"available", func() ([]schema.Record, error) { return want, nil }},
	})
	if err != nil || len(records) != 1 || records[0]["key"] != "pkg|1" {
		t.Fatalf("available source was not preserved: records=%v err=%v", records, err)
	}
}

func TestReadOptionalTrimDistinguishesAbsenceFromReadFailure(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	if value, err := readOptionalTrim(missing); value != "" || err != nil {
		t.Fatalf("missing optional source should be absent: value=%q err=%v", value, err)
	}
	directory := t.TempDir()
	if _, err := readOptionalTrim(directory); err == nil {
		t.Fatal("non-readable source shape was suppressed")
	}
}
