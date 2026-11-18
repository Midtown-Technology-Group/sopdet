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

func TestTargetIDIsExactAndHidesEndpoint(t *testing.T) {
	const ep = "https://bifrost.example.test/api/endpoints/00000000-0000-4000-8000-000000000001"
	const key = "synthetic-key-a"
	if got := TargetID("", key); got != LocalTarget {
		t.Fatalf("empty endpoint = %q, want %q", got, LocalTarget)
	}
	a := TargetID(ep, key)
	if a != TargetID(ep, key) {
		t.Fatal("the same endpoint and key produced different targets")
	}
	// Exact, like the ingest spool scope: another spelling or another key is
	// another target, so its baseline never outruns chunks spooled under this one.
	others := map[string][2]string{
		"trailing slash":   {ep + "/", key},
		"leading space":    {" " + ep, key},
		"other endpoint":   {ep + "x", key},
		"other key":        {ep, "synthetic-key-b"},
		"no key":           {ep, ""},
		"shifted boundary": {ep + "s", "ynthetic-key-a"},
	}
	for name, o := range others {
		if TargetID(o[0], o[1]) == a {
			t.Fatalf("%s shares a target", name)
		}
	}
	if a == LocalTarget {
		t.Fatal("a posting target equals the local target")
	}
	if len(a) != len("sha256:")+64 || a[:7] != "sha256:" {
		t.Fatalf("target %q is not a sha256 digest", a)
	}
}

func TestBaselineForOnlyMatchesItsTarget(t *testing.T) {
	entities := map[string]*schema.EntityCollection{
		"os": schema.BuildEntity([]schema.Record{{"key": "os", "name": "X"}}, ts),
	}
	a := TargetID("https://bifrost.example.test/api/endpoints/a", "synthetic-key")
	b := TargetID("https://bifrost.example.test/api/endpoints/b", "synthetic-key")
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
