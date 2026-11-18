package state

import (
	"path/filepath"
	"testing"

	"github.com/Midtown-Technology-Group/sopdet/internal/schema"
)

const ts = "2026-01-01T00:00:00Z"

func TestBuildDelta(t *testing.T) {
	prev := map[string]*schema.EntityCollection{
		"software": schema.BuildEntity([]schema.Record{
			{"key": "1", "v": "a"},
			{"key": "2", "v": "b"},
		}, ts),
	}
	snap := Snapshot("scan-1", ts, "test", schema.FingerprintAlgo, LocalTarget, prev)

	cur := map[string]*schema.EntityCollection{
		"software": schema.BuildEntity([]schema.Record{
			{"key": "1", "v": "changed"},
			{"key": "3", "v": "new"},
		}, ts),
	}
	d := BuildDelta(cur, snap.AsMaps())["software"]
	if d == nil {
		t.Fatal("nil delta")
	}
	if len(d.Added) != 1 || d.Added[0]["key"] != "3" {
		t.Fatalf("added=%v", d.Added)
	}
	if len(d.Changed) != 1 || d.Changed[0]["key"] != "1" {
		t.Fatalf("changed=%v", d.Changed)
	}
	if len(d.Removed) != 1 || d.Removed[0].Key != "2" {
		t.Fatalf("removed=%v", d.Removed)
	}
	if d.Count != 2 || d.Unchanged != 0 {
		t.Fatalf("count=%d unchanged=%d", d.Count, d.Unchanged)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	entities := map[string]*schema.EntityCollection{
		"os": schema.BuildEntity([]schema.Record{{"key": "os", "name": "X"}}, ts),
	}
	s := Snapshot("scan-9", ts, "test", schema.FingerprintAlgo, LocalTarget, entities)
	if err := Save(path, s); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil || got == nil {
		t.Fatalf("load: %v %v", got, err)
	}
	if got.ScanID != "scan-9" || got.AsMaps()["os"]["os"] != s.AsMaps()["os"]["os"] {
		t.Fatalf("mismatch: %+v", got)
	}
}

func TestRemoveToleratesAbsentState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := Remove(path); err != nil {
		t.Fatalf("absent state: %v", err)
	}
	s := Snapshot("scan-1", ts, "test", schema.FingerprintAlgo, LocalTarget, nil)
	if err := Save(path, s); err != nil {
		t.Fatal(err)
	}
	if err := Remove(path); err != nil {
		t.Fatal(err)
	}
	if got, err := Load(path); err != nil || got != nil {
		t.Fatalf("state survived removal: %v %v", got, err)
	}
}

func TestBaselineForOnlyMatchesItsTarget(t *testing.T) {
	entities := map[string]*schema.EntityCollection{
		"os": schema.BuildEntity([]schema.Record{{"key": "os", "name": "X"}}, ts),
	}
	const a, b = "go-0123456789abcdef0123456789abcdef", "go-fedcba9876543210fedcba9876543210"
	s := Snapshot("scan-1", ts, "test", schema.FingerprintAlgo, a, entities)
	if s.BaselineFor(a) == nil {
		t.Fatal("baseline not used for the target it was delivered to")
	}
	for name, target := range map[string]string{"other endpoint": b, "local run": LocalTarget} {
		if s.BaselineFor(target) != nil {
			t.Fatalf("%s reused a baseline delivered elsewhere", name)
		}
	}
	legacy := *s
	legacy.Target = ""
	if legacy.BaselineFor(a) != nil || legacy.BaselineFor(LocalTarget) != nil {
		t.Fatal("state without a recorded target was trusted as a baseline")
	}
	var none *State
	if none.BaselineFor(a) != nil {
		t.Fatal("nil state produced a baseline")
	}
}
