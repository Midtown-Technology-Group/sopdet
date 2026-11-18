package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	// staleScriptPattern matches only the temp script files this agent
	// stages via writeTempScript (Runner.Run removes its own file on
	// every return; the sweep below covers the leftovers from crashes,
	// kills, and power loss).
	staleScriptPattern = "sopdet-job-*.ps1"
	// staleScriptTTL bounds the sweep: only files older than this are
	// removed. Age keeps recent scripts — including a concurrent agent's
	// fresh script — but it is not unconditional protection: a foreign
	// job running longer than the TTL while sharing this dir could lose
	// its script. The sweep runs once at serve startup, before this
	// process stages any script, so this agent's own active file can
	// never exist yet when the sweep runs. 24h is deliberately
	// conservative for a transient file.
	staleScriptTTL = 24 * time.Hour
)

// SweepStaleScripts removes stale per-job script staging files left in dir
// by abnormal shutdowns (Runner.Run already removes its own script on every
// normal return). It is bounded:
//
//   - dir must be an explicitly configured work dir; "" never sweeps (that
//     would mean the shared os.TempDir());
//   - only top-level entries matching staleScriptPattern — no recursion,
//     so nested directories are never entered;
//   - only plain regular files — symlinks, directories, and other modes
//     are skipped, never followed;
//   - only files older than staleScriptTTL — recent scripts are
//     preserved, but age alone is not unconditional protection for a
//     concurrent foreign job running longer than the TTL in the same
//     dir (see the TTL comment above).
//
// It returns the number of files removed. A missing dir is not an error.
func SweepStaleScripts(dir string) (int, error) {
	return sweepStaleScripts(dir, os.Lstat, os.Remove)
}

// Injectable filesystem calls let race and I/O failures be tested without
// changing permissions on a real work directory.
func sweepStaleScripts(dir string, lstat func(string) (os.FileInfo, error), remove func(string) error) (int, error) {
	if dir == "" {
		return 0, nil
	}
	clean := filepath.Clean(dir)
	entries, err := os.ReadDir(clean)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	cutoff := time.Now().Add(-staleScriptTTL)
	removed := 0
	for _, e := range entries {
		path, err := staleScriptPath(clean, e, cutoff, lstat)
		if err != nil {
			return removed, fmt.Errorf("sweep after removing %d: %w", removed, err)
		}
		if path == "" {
			continue
		}
		if err := remove(path); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue // concurrently removed
			}
			return removed, fmt.Errorf("remove stale script %s after removing %d: %w", path, removed, err)
		}
		removed++
	}
	return removed, nil
}

func staleScriptPath(dir string, e os.DirEntry, cutoff time.Time, lstat func(string) (os.FileInfo, error)) (string, error) {
	if e.IsDir() {
		return "", nil
	}
	ok, err := filepath.Match(staleScriptPattern, e.Name())
	if err != nil || !ok {
		return "", nil
	}
	// ReadDir gives only direct child names. Keep the joined path anchored
	// inside the explicitly configured work directory.
	path := filepath.Join(dir, e.Name())
	if filepath.Dir(path) != dir {
		return "", nil
	}
	info, err := lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil // concurrently removed
	}
	if err != nil {
		return "", fmt.Errorf("inspect stale script %s: %w", path, err)
	}
	if !info.Mode().IsRegular() || !info.ModTime().Before(cutoff) {
		return "", nil // symlink, special file, or fresh script
	}
	return path, nil
}
