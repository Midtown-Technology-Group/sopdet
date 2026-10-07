package agent

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// stageFixture creates a synthetic sopdet-job-style file with the given age.
func stageFixture(t *testing.T, dir, name string, age time.Duration) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("Write-Output 'synthetic'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().Add(-age)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	return path
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func TestSweepStaleScriptsBounds(t *testing.T) {
	work := t.TempDir()

	stale := stageFixture(t, work, "sopdet-job-abc123.ps1", 48*time.Hour)
	fresh := stageFixture(t, work, "sopdet-job-active.ps1", time.Minute)
	other := stageFixture(t, work, "notes.txt", 48*time.Hour)
	otherPattern := stageFixture(t, work, "sopdet-job-old.log", 48*time.Hour)

	// Nested match: recursion must never enter subdirectories.
	sub := filepath.Join(work, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	nested := stageFixture(t, sub, "sopdet-job-nested.ps1", 48*time.Hour)

	// Symlink with a matching name: never followed, never removed.
	linkTarget := stageFixture(t, work, "real-target.ps1", 48*time.Hour)
	link := filepath.Join(work, "sopdet-job-link.ps1")
	if err := os.Symlink(linkTarget, link); err != nil {
		t.Fatal(err)
	}

	removed, err := SweepStaleScripts(work)
	if err != nil {
		t.Fatalf("SweepStaleScripts: %v", err)
	}
	if removed != 1 {
		t.Errorf("removed = %d, want 1 (only the stale top-level match)", removed)
	}
	if exists(stale) {
		t.Errorf("stale script was not removed: %s", stale)
	}
	for _, want := range []string{fresh, other, otherPattern, nested, link, linkTarget} {
		if !exists(want) {
			t.Errorf("protected file was removed: %s", want)
		}
	}
}

func TestSweepStaleScriptsEmptyAndMissing(t *testing.T) {
	if n, err := SweepStaleScripts(""); err != nil || n != 0 {
		t.Errorf("empty dir: got (%d, %v), want (0, nil)", n, err)
	}
	if n, err := SweepStaleScripts(filepath.Join(t.TempDir(), "absent")); err != nil || n != 0 {
		t.Errorf("missing dir: got (%d, %v), want (0, nil)", n, err)
	}
	if n, err := SweepStaleScripts(t.TempDir()); err != nil || n != 0 {
		t.Errorf("clean dir: got (%d, %v), want (0, nil)", n, err)
	}
}
